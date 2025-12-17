package providers

import (
	"context"
	"fmt"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/darmiel/talmi/internal/core"
)

type StubProvider struct {
	name string
}

func (s *StubProvider) Name() string {
	return s.name
}

func (s *StubProvider) Mint(
	ctx context.Context,
	principal *core.Principal,
	grant core.Grant,
) (*core.TokenArtifact, error) {
	logger := log.Ctx(ctx)
	logger.Info().
		Str("provider", s.name).
		Str("principal_id", principal.ID).
		Msg("StubProvider Mint called")

	tok := fmt.Sprintf("talmi_v1_fake_token_for_%s", grant.Provider)

	return &core.TokenArtifact{
		Value:       tok,
		Fingerprint: CalculateFingerprinter(StubFingerprintType, tok),
		ExpiresAt:   time.Now().Add(1 * time.Hour),
		Metadata: map[string]any{
			"env": "stub",
		},
	}, nil
}
