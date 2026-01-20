package providers

import (
	"fmt"

	"github.com/darmiel/talmi/internal/config"
	"github.com/darmiel/talmi/internal/core"
	githubprovider "github.com/darmiel/talmi/internal/providers/github"
	jfrogprovider "github.com/darmiel/talmi/internal/providers/jfrog"
	stubprovider "github.com/darmiel/talmi/internal/providers/stub"
	talmiprovider "github.com/darmiel/talmi/internal/providers/talmi"
)

func BuildRegistry(cfgs []config.ProviderConfig, signingKey []byte) (map[string]core.Provider, error) {
	registry := make(map[string]core.Provider)
	for _, cfg := range cfgs {
		var p core.Provider
		var err error

		switch cfg.Type {
		case githubprovider.Type:
			p, err = githubprovider.NewFromConfig(cfg)
		case jfrogprovider.Type:
			p, err = jfrogprovider.NewFromConfig(cfg)
		case stubprovider.Type:
			p, err = stubprovider.New(cfg)
		case talmiprovider.Type:
			p, err = talmiprovider.NewFromConfig(cfg, signingKey)
		default:
			return nil, fmt.Errorf("unknown provider type %q for provider %q", cfg.Type, cfg.Name)
		}

		if err != nil {
			return nil, fmt.Errorf("failed to create provider %q of type %q: %w", cfg.Name, cfg.Type, err)
		}
		registry[cfg.Name] = p
	}
	return registry, nil
}
