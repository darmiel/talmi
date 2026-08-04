package issuers

import (
	"context"
	"fmt"

	"github.com/darmiel/talmi/internal/config"
	"github.com/darmiel/talmi/internal/core"
)

var _ core.Issuer = (*StaticIssuer)(nil)

type StaticIssuer struct {
	name     string
	tokenMap map[string]map[string]any // token -> attributes
}

func NewStatic(name string, cfg config.StaticConfig) (*StaticIssuer, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("static issuer %q: %w", name, err)
	}
	return &StaticIssuer{
		name:     name,
		tokenMap: cfg.TokenMap,
	}, nil
}

func (s *StaticIssuer) Name() string {
	return s.name
}

func (s *StaticIssuer) Verify(_ context.Context, token string) (*core.Principal, error) {
	attrs, ok := s.tokenMap[token]
	if !ok {
		return nil, fmt.Errorf("invalid token: %s", token)
	}
	return &core.Principal{
		ID:         "static-user",
		Issuer:     s.name,
		Attributes: attrs,
	}, nil
}
