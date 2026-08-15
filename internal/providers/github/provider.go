package github

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/google/go-github/v80/github"
	"github.com/rs/zerolog/log"

	"github.com/darmiel/talmi/internal/audit"
	"github.com/darmiel/talmi/internal/core"
	"github.com/darmiel/talmi/internal/correlation"
)

const Type = "github-app"

var info = core.ProviderInfo{
	Type:    Type,
	Version: "v2",
}

var (
	_ core.ResourceProvider = (*Provider)(nil)
	_ core.TokenRevoker     = (*Provider)(nil)
)

// Provider implements core.Provider by minting GitHub App installation tokens.
// It supports GitHub Cloud and GitHub Enterprise.
// The provider requires configuration of the App ID and the private key.
type Provider struct {
	name          string
	realm         string
	appID         int64
	privateKey    []byte
	serverBaseURL string

	capTTL time.Duration
	mu     sync.Mutex
	cached *cachedCapability

	httpTimeout time.Duration

	discover func(ctx context.Context) (*discovered, error)
}

type discovered struct {
	appActions     []core.Action
	installByOwner map[string]int64
	reposByOwner   map[string][]string
}

type cachedCapability struct {
	data      *discovered
	expiresAt time.Time
}

type ghMintPlan struct {
	installationID int64
	repos          []string
	perms          map[string]string
}

// New creates a new Provider from the given config.
// It maps a ProviderConfig to ProviderConfig struct,
func New(name, realm string, cfg ProviderConfig) (*Provider, error) {
	if len(cfg.PrivateKey) == 0 {
		return nil, fmt.Errorf("github-app provider %q missing 'private_key'", name)
	}

	capTTL := cfg.RefreshInterval
	if capTTL <= 0 {
		capTTL = 15 * time.Minute
	}
	if capTTL < 1*time.Minute {
		log.Warn().
			Str("provider", name).
			Dur("refresh_interval", capTTL).
			Msg("github: capability cache refresh interval is very low, consider increasing it to avoid rate limiting")
	}

	httpTimeout := cfg.Timeout
	if httpTimeout <= 0 {
		httpTimeout = DefaultHTTPTimeout
	}

	p := &Provider{
		name:          name,
		realm:         realm,
		appID:         cfg.AppID,
		privateKey:    cfg.PrivateKey,
		serverBaseURL: cfg.ServerBaseURL,
		capTTL:        capTTL,
		httpTimeout:   httpTimeout,
	}
	p.discover = p.discoverViaAPI

	return p, nil
}

type ProviderConfig struct {
	AppID      int64
	PrivateKey []byte

	// Optional: GitHub Enterprise server URL. Defaults to https://api.github.com
	ServerBaseURL string

	// RefreshInterval is the capability cache TTL.
	RefreshInterval time.Duration

	// Timeout for each HTTP call to GitHub. 0 = default (30s)
	Timeout time.Duration
}

func (p *Provider) Name() string {
	return p.name
}

func (p *Provider) Realm() string {
	return p.realm
}

// Invalidate drops the capability cache
func (p *Provider) Invalidate() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.cached = nil
	log.Info().
		Str("provider", p.name).
		Msg("github: capability cache invalidated")
}

func (p *Provider) Capabilities(ctx context.Context) (core.Capability, error) {
	d, err := p.discoveredCapability(ctx)
	if err != nil {
		return core.Capability{}, err
	}

	resources := make([]string, 0)
	for owner, repos := range d.reposByOwner {
		for _, repo := range repos {
			resources = append(resources, fmt.Sprintf("%s:%s/%s", p.realm, owner, repo))
		}
	}

	return core.Capability{
		Realm:      p.realm,
		Resources:  resources,
		MaxActions: d.appActions,
	}, nil
}

func (p *Provider) Plan(ctx context.Context, requests []core.ResourceRequest) ([]core.MintPlan, error) {
	d, err := p.discoveredCapability(ctx)
	if err != nil {
		return nil, err
	}

	type repoPerms struct {
		perms  map[string]string
		covers []core.ResourceRequest
	}
	byOwnerRepo := make(map[string]map[string]*repoPerms)
	for _, r := range requests {
		owner, repo, ok := splitOwnerRepo(r.Resource)
		if !ok {
			return nil, fmt.Errorf("malformed github resource %q", r.Resource)
		}
		if byOwnerRepo[owner] == nil {
			byOwnerRepo[owner] = make(map[string]*repoPerms)
		}
		rp := byOwnerRepo[owner][repo]
		if rp == nil {
			rp = &repoPerms{perms: make(map[string]string)}
			byOwnerRepo[owner][repo] = rp
		}
		rp.covers = append(rp.covers, r)
		addPerms(rp.perms, r.Actions)
	}

	var plans []core.MintPlan
	for owner, repos := range byOwnerRepo {
		installationID, ok := d.installByOwner[owner]
		if !ok {
			return nil, fmt.Errorf("no installation found for owner %q", owner)
		}
		groups := make(map[string]*ghMintPlan)
		covers := make(map[string][]core.ResourceRequest)
		for repo, rp := range repos {
			key := permSetKey(rp.perms)
			g := groups[key]
			if g == nil {
				g = &ghMintPlan{
					installationID: installationID,
					perms:          rp.perms,
				}
				groups[key] = g
			}
			g.repos = append(g.repos, repo)
			covers[key] = append(covers[key], rp.covers...)
		}

		for key, g := range groups {
			slices.Sort(g.repos)
			plans = append(plans, core.MintPlan{
				Provider: p.name,
				Realm:    p.realm,
				Covers:   covers[key],
				Internal: *g,
			})
		}
	}

	return plans, nil
}

// splitOwnerRepo splits a resource of the form "owner/repo" into its components.
func splitOwnerRepo(resource core.Resource) (owner, repo string, ok bool) {
	body := resource.Body()
	i := strings.IndexByte(body, '/')
	if i <= 0 || i == len(body)-1 {
		return "", "", false
	}
	return body[:i], body[i+1:], true
}

// reposIn returns a sorted list of unique repositories in the given group of resource requests.
func reposIn(group []core.ResourceRequest) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, r := range group {
		if _, repo, ok := splitOwnerRepo(r.Resource); ok {
			if _, dup := seen[repo]; !dup {
				seen[repo] = struct{}{}
				out = append(out, repo)
			}
		}
	}
	slices.Sort(out)
	return out
}

func addPerms(dst map[string]string, actions []core.Action) {
	for _, a := range actions {
		perm, lvlStr, ok := strings.Cut(string(a), ":")
		if !ok {
			continue
		}
		lvl := parseLevel(lvlStr)
		if lvl == LevelNone {
			continue
		}
		if cur, exists := dst[perm]; !exists || lvl > parseLevel(cur) {
			dst[perm] = lvlStr
		}
	}
}

func permSetKey(perms map[string]string) string {
	keys := make([]string, 0, len(perms))
	for k := range perms {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	var bob strings.Builder
	for _, k := range keys {
		bob.WriteString(k)
		bob.WriteByte('=')
		bob.WriteString(perms[k])
		bob.WriteByte(';')
	}
	return bob.String()
}

func (p *Provider) Mint(
	ctx context.Context,
	principal *core.Principal,
	plan core.MintPlan,
) (*core.TokenArtifact, error) {
	mp, ok := plan.Internal.(ghMintPlan)
	if !ok {
		return nil, fmt.Errorf("github mint: unexpected plan payload %T", plan.Internal)
	}

	appClient, err := p.createAppClient(ctx, principal.ID)
	if err != nil {
		return nil, fmt.Errorf("creating github app client: %w", err)
	}

	var perms github.InstallationPermissions
	if len(mp.perms) == 0 {
		return nil, fmt.Errorf("github mint: refusing to mint installation token with no explicit permissions")
	}
	b, err := json.Marshal(mp.perms)
	if err != nil {
		return nil, fmt.Errorf("marshaling permissions: %w", err)
	}
	if err := json.Unmarshal(b, &perms); err != nil {
		return nil, fmt.Errorf("unmarshaling permissions: %w", err)
	}
	opts := &github.InstallationTokenOptions{
		Permissions:  &perms,
		Repositories: mp.repos,
	}

	log.Ctx(ctx).Debug().
		Str("provider", p.name).
		Int64("installation", mp.installationID).
		Strs("repos", mp.repos).
		Int("permissions", len(mp.perms)).
		Msg("github: minting installation token")

	installationToken, _, err := appClient.Apps.CreateInstallationToken(ctx, mp.installationID, opts)
	if err != nil {
		return nil, fmt.Errorf("creating installation token for %d: %w", mp.installationID, err)
	}

	token := installationToken.GetToken()
	artifact := &core.TokenArtifact{
		Value:       token,
		ExpiresAt:   installationToken.GetExpiresAt().Time,
		Fingerprint: audit.CalculateFingerprint(audit.GitHubFingerprintType, token),
		Provider:    info,
		Metadata: map[string]any{
			"installation": mp.installationID,
			"repositories": mp.repos,
			"permissions":  installationToken.GetPermissions(),
		},
	}

	// we don't _need_ this, because we revoke tokens by the token itself, but it's useful for revocation tracking
	artifact.SetRevocationID(fmt.Sprintf("github-installation-%d", mp.installationID))

	log.Ctx(ctx).Debug().
		Str("provider", p.name).
		Int64("installation", mp.installationID).
		Time("expires_at", artifact.ExpiresAt).
		Msg("github: installation token minted")

	return artifact, nil
}

func (p *Provider) Revoke(ctx context.Context, revocationID, tokenVal string) error {
	logger := log.Ctx(ctx)
	logger.Debug().
		Str("provider", p.name).
		Str("revocation_id", revocationID).
		Msg("github: revoking installation token")

	if tokenVal == "" {
		return fmt.Errorf("original token required for %T token revocation", Type)
	}

	client, err := NewRawClient(tokenVal, p.serverBaseURL, p.httpTimeout)
	if err != nil {
		return fmt.Errorf("creating github client for revocation: %w", err)
	}

	_, err = client.Apps.RevokeInstallationToken(ctx)
	if err != nil {
		if ghErr, ok := errors.AsType[*github.ErrorResponse](err); ok &&
			ghErr.Response != nil && (ghErr.Response.StatusCode == http.StatusUnauthorized ||
			ghErr.Response.StatusCode == http.StatusNotFound) {

			logger.Debug().
				Str("provider", p.name).
				Str("revocation_id", revocationID).
				Int("status", ghErr.Response.StatusCode).
				Msg("github: token already invalid, treating revoke as success")
			return nil
		}
		return fmt.Errorf("revoking github installation token: %w", err)
	}

	logger.Debug().
		Str("provider", p.name).
		Str("revocation_id", revocationID).
		Msg("github: installation token revoked")
	return nil
}

// RequiresTokenForRevocation indicates that the GitHub provider requires the original token to revoke it.
func (p *Provider) RequiresTokenForRevocation() bool {
	return true
}

func (p *Provider) createAppClient(ctx context.Context, principalID string) (*github.Client, error) {
	correlationID := correlation.From(ctx)

	client, err := NewClient(p.appID, p.privateKey, p.serverBaseURL, p.httpTimeout)
	if err != nil {
		return nil, err
	}
	// set user agent for auditing
	client.UserAgent = audit.CreateUserAgent(correlationID, principalID, p.Name())

	return client, nil
}
