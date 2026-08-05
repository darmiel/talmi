package source

import (
	"fmt"

	"github.com/darmiel/talmi/internal/config"
	"github.com/darmiel/talmi/internal/secret"
)

type Options struct {
	// ForceLocal bypasses any configured remote source and reads local disk.
	ForceLocal bool
	// Ref overrides the revision for git-backed sources.
	Ref string
}

type sourceKind int

const (
	kindLocal sourceKind = iota
	kindGitHub
)

// plan decides which source to build and the effective git ref.
func plan(cfg *config.Config, opts Options) (kind sourceKind, ref string, err error) {
	useGitHub := cfg.ConfigSource != nil && cfg.ConfigSource.GitHub != nil && !opts.ForceLocal
	if !useGitHub {
		if opts.Ref != "" {
			return kindLocal, "", fmt.Errorf("ref override requires a remote config source")
		}
		return kindLocal, "", nil
	}
	ref = cfg.ConfigSource.GitHub.Ref
	if opts.Ref != "" {
		ref = opts.Ref // override from config
	}
	return kindGitHub, ref, nil
}

// Resolve selects and constructs the config Source for cfg, applying opts.
func Resolve(cfg *config.Config, baseDir string, opts Options) (Source, error) {
	kind, ref, err := plan(cfg, opts)
	if err != nil {
		return nil, err
	}
	if kind == kindLocal {
		return NewLocalSource(baseDir, cfg), nil
	}

	gh := *cfg.ConfigSource.GitHub
	gh.Ref = ref
	key, err := secret.Resolve(gh.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("resolving source private key: %w", err)
	}
	return NewGitHubSource(gh, key)
}
