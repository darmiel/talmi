package stub

import (
	"context"
	"fmt"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/darmiel/talmi/internal/audit"
	"github.com/darmiel/talmi/internal/core"
)

const Type = "stub"

var info = core.ProviderInfo{
	Type:    Type,
	Version: "v1",
}

var _ core.Provider = (*Provider)(nil)

type Provider struct {
	name string
}

// New creates a new Provider with the given name.
func New(name string) (*Provider, error) {
	return &Provider{
		name: name,
	}, nil
}

func (s *Provider) Name() string {
	return s.name
}

func (s *Provider) Downscope(allowed, _ map[string]string) (map[string]string, error) {
	return allowed, nil // No downscoping for stub provider
}

func (s *Provider) Mint(
	ctx context.Context,
	principal *core.Principal,
	grant core.Grant,
) (*core.TokenArtifact, error) {
	logger := log.Ctx(ctx)
	logger.Info().
		Str("provider", s.name).
		Str("principal_id", principal.ID).
		Msg("StubProvider Mint called")

	tok := fmt.Sprintf("talmi_v1_fake_token_for_%s_%d", grant.Provider, time.Now().Unix())

	return &core.TokenArtifact{
		Value:       tok,
		Fingerprint: audit.CalculateFingerprint(audit.StubFingerprintType, tok),
		ExpiresAt:   time.Now().Add(1 * time.Hour),
		Provider:    info,
		Metadata: map[string]any{
			"env": "stub",
		},
	}, nil
}
