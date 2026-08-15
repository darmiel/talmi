package jfrog

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/darmiel/talmi/internal/core"
)

const Type = "jfrog-artifactory"

var info = core.ProviderInfo{
	Type:    Type,
	Version: "v2",
}

var (
	_ core.ResourceProvider = (*Provider)(nil)
	_ core.TokenRevoker     = (*Provider)(nil)
)

type Provider struct {
	name          string
	realm         string
	serverBaseURL string
	token         string
	groups        []string
	resources     []string
	maxAction     []core.Action
	defaultTTL    time.Duration
	httpClient    *http.Client
}

type ProviderConfig struct {
	Server     string
	Token      string
	Groups     []string
	Resources  []string
	MaxActions []core.Action
	DefaultTTL time.Duration
	Timeout    time.Duration
}

func New(name, realm string, cfg ProviderConfig) (*Provider, error) {
	normalizedServerBaseURL := strings.TrimRight(cfg.Server, "/")
	switch {
	case normalizedServerBaseURL == "":
		return nil, fmt.Errorf("jfrog artifactory provider %q: server is required", name)
	case cfg.Token == "":
		return nil, fmt.Errorf("jfrog artifactory provider %q: token is required", name)
	case len(cfg.Groups) == 0:
		// without groups the minted token would be unscoped which we refuse (for now).
		return nil, fmt.Errorf("jfrog artifactory provider %q: at least one group is required", name)
	}

	ttl := cfg.DefaultTTL
	if ttl <= 0 {
		ttl = 1 * time.Hour
	}

	httpTimeout := cfg.Timeout
	if httpTimeout <= 0 {
		httpTimeout = 30 * time.Second
	}

	return &Provider{
		name:          name,
		realm:         realm,
		serverBaseURL: normalizedServerBaseURL,
		token:         cfg.Token,
		groups:        slices.Clone(cfg.Groups),
		resources:     slices.Clone(cfg.Resources),
		maxAction:     slices.Clone(cfg.MaxActions),
		defaultTTL:    ttl,
		httpClient:    &http.Client{Timeout: httpTimeout},
	}, nil
}

func (p *Provider) Name() string {
	return p.name
}

func (p *Provider) Realm() string {
	return p.realm
}

func (p *Provider) Capabilities(_ context.Context) (core.Capability, error) {
	return core.Capability{
		Realm:      p.realm,
		Resources:  p.resources,
		MaxActions: p.maxAction,
	}, nil
}

// Plan batches all requests into one token
func (p *Provider) Plan(_ context.Context, requests []core.ResourceRequest) ([]core.MintPlan, error) {
	if len(requests) == 0 {
		return nil, nil
	}
	return []core.MintPlan{
		{
			Provider: p.name,
			Realm:    p.realm,
			Covers:   slices.Clone(requests),
		},
	}, nil
}

func (p *Provider) Mint(
	ctx context.Context,
	principal *core.Principal,
	plan core.MintPlan,
) (*core.TokenArtifact, error) {
	logger := log.Ctx(ctx)
	scope := groupScope(p.groups)
	description := fmt.Sprintf("[talmi for %s]", principal.ID)

	logger.Info().
		Str("provider", p.name).
		Str("scope", scope).
		Str("description", description).
		Msg("minting JFrog Artifactory token")

	resp, err := p.CreateToken(ctx, principal.ID, &CreateTokenRequest{
		Scope:                 scope,
		ExpiresIn:             int64(p.defaultTTL / time.Second),
		Refreshable:           false,
		Description:           description,
		IncludeReferenceToken: false,
	})
	if err != nil {
		return nil, fmt.Errorf("creating jfrog artifactory token: %w", err)
	}

	responseExpiresIn := resp.ExpiresIn
	if responseExpiresIn <= 0 {
		// this token looks to be permanent, so we set a far future expiry time
		responseExpiresIn = 60 * 60 * 24 * 365 * 100
	}

	artifact := &core.TokenArtifact{
		Value:     resp.AccessToken,
		ExpiresAt: time.Now().Add(time.Duration(responseExpiresIn) * time.Second),
		Provider:  info,
		Metadata: map[string]any{
			"token_id":   resp.TokenID,
			"token_type": resp.TokenType,
			"scope":      resp.Scope,
			"username":   resp.Username,
			"covers":     coveredResources(plan.Covers),
		},
	}
	artifact.SetRevocationID(resp.TokenID) // JFrog tokens can be revoked by their token ID

	logger.Debug().
		Str("provider", p.name).
		Str("token_id", resp.TokenID).
		Time("expires_at", artifact.ExpiresAt).
		Msg("JFrog Artifactory token minted")

	return artifact, nil
}

func (p *Provider) Revoke(ctx context.Context, revocationID, _ string) error {
	logger := log.Ctx(ctx)
	if revocationID == "" {
		return fmt.Errorf("revoking jfrog artifactory token: revocation ID is empty")
	}
	logger.Debug().
		Str("provider", p.name).
		Str("revocation_id", revocationID).
		Msg("jfrog: revoking token")
	if err := p.RevokeToken(ctx, revocationID); err != nil {
		return fmt.Errorf("revoking jfrog artifactory token ID %s: %w", revocationID, err)
	}
	logger.Debug().
		Str("provider", p.name).
		Str("revocation_id", revocationID).
		Msg("jfrog: token revoked")
	return nil
}

func (p *Provider) RequiresTokenForRevocation() bool {
	return false
}

// groupScope builds a JFrog "applied-permission/groups" scope, quoting each group so names with spaces
// or commas are handled correctly.
func groupScope(groups []string) string {
	quoted := make([]string, len(groups))
	for i, g := range groups {
		quoted[i] = strconv.Quote(g)
	}
	return "applied-permissions/groups:" + strings.Join(quoted, ",")
}

func coveredResources(covers []core.ResourceRequest) []string {
	out := make([]string, len(covers))
	for i, c := range covers {
		out[i] = string(c.Resource)
	}
	return out
}
