package stub

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/darmiel/talmi/internal/audit"
	"github.com/darmiel/talmi/internal/core"
)

const Type = "stub"

var info = core.ProviderInfo{
	Type:    Type,
	Version: "v2",
}

var (
	_ core.ResourceProvider = (*Provider)(nil)
	_ core.TokenRevoker     = (*Provider)(nil)
)

type Provider struct {
	name       string
	realm      string
	resources  []string
	maxActions []core.Action
	ttl        time.Duration
	mintErr    error
	revokeErr  error
	capError   error
	mu         sync.Mutex
	revoked    []string
}

type Option func(*Provider)

func WithResources(patterns ...string) Option {
	return func(provider *Provider) {
		provider.resources = patterns
	}
}

func WithMaxActions(actions ...core.Action) Option {
	return func(provider *Provider) {
		provider.maxActions = actions
	}
}

func WithTTL(ttl time.Duration) Option {
	return func(provider *Provider) {
		provider.ttl = ttl
	}
}

func WithMintError(err error) Option {
	return func(provider *Provider) {
		provider.mintErr = err
	}
}

func WithRevokeError(err error) Option {
	return func(provider *Provider) {
		provider.revokeErr = err
	}
}

func WithCapabilitiesError(err error) Option {
	return func(provider *Provider) {
		provider.capError = err
	}
}

func New(name, realm string, opts ...Option) *Provider {
	p := &Provider{
		name:  name,
		realm: realm,
		ttl:   time.Hour,
	}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

func (p *Provider) Name() string {
	return p.name
}

func (p *Provider) Realm() string {
	return p.realm
}

func (p *Provider) Capabilities(_ context.Context) (core.Capability, error) {
	if p.capError != nil {
		return core.Capability{}, p.capError
	}
	return core.Capability{
		Realm:      p.realm,
		Resources:  p.resources,
		MaxActions: p.maxActions,
	}, nil
}

// Plan batches every given request into a single mintable batch.
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

func (p *Provider) Mint(_ context.Context, principal *core.Principal, plan core.MintPlan) (*core.TokenArtifact, error) {
	if p.mintErr != nil {
		return nil, p.mintErr
	}
	token := fmt.Sprintf("stub:%s:%s:%s", p.name, principal.ID, coversKey(plan.Covers))
	artifact := &core.TokenArtifact{
		Value:       token,
		Fingerprint: audit.CalculateFingerprint(audit.StubFingerprintType, token),
		ExpiresAt:   time.Now().Add(p.ttl),
		Provider:    info,
		Metadata: map[string]any{
			"realm":  p.realm,
			"covers": coversKey(plan.Covers),
		},
	}
	artifact.SetRevocationID("stub-" + p.name)
	return artifact, nil
}

func (p *Provider) Revoke(_ context.Context, revocationID, _ string) error {
	if p.revokeErr != nil {
		return p.revokeErr
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	p.revoked = append(p.revoked, revocationID)
	return nil
}

func (p *Provider) Revoked() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Clone(p.revoked)
}

func coversKey(covers []core.ResourceRequest) string {
	res := make([]string, 0, len(covers))
	for _, c := range covers {
		res = append(res, string(c.Resource))
	}
	slices.Sort(res)
	return strings.Join(res, ",")
}
