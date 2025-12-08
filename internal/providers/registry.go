package providers

import (
	"fmt"

	"github.com/darmiel/talmi/internal/config"
	"github.com/darmiel/talmi/internal/core"
)

func BuildRegistry(cfgs []config.ProviderConfig) (map[string]core.Provider, error) {
	registry := make(map[string]core.Provider)
	for _, cfg := range cfgs {
		switch cfg.Type {
		case "stub":
			registry[cfg.Name] = &StubProvider{
				name: cfg.Name,
			}
		case "github_app":
			prov, err := NewGitHubAppProvider(cfg)
			if err != nil {
				return nil, fmt.Errorf("building github_app provider %q: %w", cfg.Name, err)
			}
			registry[cfg.Name] = prov
		default:
			return nil, fmt.Errorf("unknown provider type %q for provider %q", cfg.Type, cfg.Name)
		}
	}
	return registry, nil
}
