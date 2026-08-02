package source

import (
	"context"
	"fmt"

	"github.com/darmiel/talmi/internal/config"
	"github.com/darmiel/talmi/internal/core"
)

var _ Source = (*LocalSource)(nil)

// LocalSource loads the tree from disk using the include globs
type LocalSource struct {
	baseDir string
	issuers []string
	realms  []string
	rules   []string
}

func NewLocalSource(baseDir string, cfg *config.Config) *LocalSource {
	return &LocalSource{
		baseDir: baseDir,
		issuers: cfg.Issuers.Include,
		realms:  cfg.Realms.Include,
		rules:   cfg.Rules.Include,
	}
}

func (s *LocalSource) Load(_ context.Context) (*config.SourcedConfig, string, error) {
	issuers, err := config.LoadSection[config.IssuerBlock](s.baseDir, s.issuers)
	if err != nil {
		return nil, "", fmt.Errorf("loading issuers: %w", err)
	}
	realms, err := config.LoadSection[config.RealmBlock](s.baseDir, s.realms)
	if err != nil {
		return nil, "", fmt.Errorf("loading realms: %w", err)
	}
	rules, err := config.LoadSection[core.Rule](s.baseDir, s.rules)
	if err != nil {
		return nil, "", fmt.Errorf("loading rules: %w", err)
	}
	return &config.SourcedConfig{
		Issuers: issuers,
		Realms:  realms,
		Rules:   rules,
	}, "local", nil
}
