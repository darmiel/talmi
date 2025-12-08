package issuers

import (
	"context"
	"fmt"

	"github.com/darmiel/talmi/internal/config"
	"github.com/darmiel/talmi/internal/core"
)

func BuildRegistry(ctx context.Context, cfgs []config.IssuerConfig) (map[string]core.Issuer, error) {
	registry := make(map[string]core.Issuer)
	for _, cfg := range cfgs {
		switch cfg.Type {
		case "static":
			iss, err := NewStatic(cfg)
			if err != nil {
				return nil, fmt.Errorf("building static issuer %q: %w", cfg.Name, err)
			}
			registry[cfg.Name] = iss
		case "oidc":
			iss, err := NewOIDCIssuer(ctx, cfg)
			if err != nil {
				return nil, fmt.Errorf("building oidc issuer %q: %w", cfg.Name, err)
			}
			registry[cfg.Name] = iss
		default:
			return nil, fmt.Errorf("unknown issuer type %q for issuer %q", cfg.Type, cfg.Name)
		}
	}
	return registry, nil
}
