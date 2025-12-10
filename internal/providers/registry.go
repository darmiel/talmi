package providers

import (
	"fmt"

	"github.com/darmiel/talmi/internal/config"
	"github.com/darmiel/talmi/internal/core"
)

func BuildRegistry(cfgs []config.ProviderConfig, signingKey []byte) (map[string]core.Provider, error) {
	registry := make(map[string]core.Provider)
	for _, cfg := range cfgs {
		switch cfg.Type {
		case "stub":
			registry[cfg.Name] = &StubProvider{
				name: cfg.Name,
			}
		case "github-app":
			prov, err := NewGitHubAppProvider(cfg)
			if err != nil {
				return nil, fmt.Errorf("building github_app provider %q: %w", cfg.Name, err)
			}
			registry[cfg.Name] = prov
		case "talmi-jwt":
			prov, err := NewTalmiJWTProvider(cfg, signingKey)
			if err != nil {
				return nil, fmt.Errorf("building talmi_jwt provider %q: %w", cfg.Name, err)
			}
			registry[cfg.Name] = prov
		default:
			return nil, fmt.Errorf("unknown provider type %q for provider %q", cfg.Type, cfg.Name)
		}
	}
	return registry, nil
}
