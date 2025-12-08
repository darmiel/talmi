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

func (s *StubProvider) Mint(ctx context.Context, principal *core.Principal, grant core.Grant) (
	*core.TokenArtifact,
	error,
) {
	log.Info().
		Str("provider", s.name).
		Str("principal_id", principal.ID).
		Str("resource_type", grant.Resource.Type).
		Str("resource_id", grant.Resource.ID).
		Msg("StubProvider Mint called")
	return &core.TokenArtifact{
		Value:     fmt.Sprintf("talmi_v1_fake_token_for_%s", grant.Resource.ID),
		ExpiresAt: time.Now().Add(1 * time.Hour),
		Metadata: map[string]string{
			"env": "stub",
		},
	}, nil
}
