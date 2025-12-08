package issuers

import (
	"fmt"

	"github.com/darmiel/talmi/internal/config"
	"github.com/darmiel/talmi/internal/core"
)

func BuildRegistry(cfgs []config.IssuerConfig) (map[string]core.Issuer, error) {
	registry := make(map[string]core.Issuer)
	for _, cfg := range cfgs {
		switch cfg.Type {
		case "static":
			iss, err := NewStatic(cfg)
			if err != nil {
				return nil, fmt.Errorf("building static issuer %q: %w", cfg.Name, err)
			}
			registry[cfg.Name] = iss
		default:
			return nil, fmt.Errorf("unknown issuer type %q for issuer %q", cfg.Type, cfg.Name)
		}
	}
	return registry, nil
}
