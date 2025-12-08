package issuers

import (
	"context"
	"fmt"

	"github.com/darmiel/talmi/internal/config"
	"github.com/darmiel/talmi/internal/core"
)

type StaticIssuer struct {
	name     string
	tokenMap map[string]map[string]string // token -> attributes
}

func NewStatic(cfg config.IssuerConfig) (*StaticIssuer, error) {
	rawMap, ok := cfg.Config["token_map"].(map[string]any)
	if !ok {
		// if no map provided, just create an empty one, which always fails verification
		return &StaticIssuer{}, nil
	}

	tokenMap := make(map[string]map[string]string)
	for token, attrsRaw := range rawMap {
		attrsInterfaceMap, ok := attrsRaw.(map[string]any)
		if !ok {
			continue
		}
		attrsStrMap := make(map[string]string)
		for k, v := range attrsInterfaceMap {
			attrsStrMap[k] = fmt.Sprint(v)
		}
		tokenMap[token] = attrsStrMap
	}

	return &StaticIssuer{
		name:     cfg.Name,
		tokenMap: tokenMap,
	}, nil
}

func (s *StaticIssuer) Name() string {
	return s.name
}

func (s *StaticIssuer) Verify(ctx context.Context, token string) (*core.Principal, error) {
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
