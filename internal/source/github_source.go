package source

import (
	"context"
	"fmt"
	"strings"

	"github.com/goccy/go-yaml"
	"github.com/google/go-github/v80/github"
	"github.com/rs/zerolog/log"

	"github.com/darmiel/talmi/internal/config"
	"github.com/darmiel/talmi/internal/core"
	githubprovider "github.com/darmiel/talmi/internal/providers/github"
)

var _ Source = (*GitHubSource)(nil)

// GitHubSource loads the tree from a GitHub repository. The app private key is resolved by the caller.
type GitHubSource struct {
	cfg        config.GitHubSource
	privateKey []byte
}

func NewGitHubSource(cfg config.GitHubSource, privateKey []byte) (*GitHubSource, error) {
	if cfg.Owner == "" || cfg.Repo == "" {
		return nil, fmt.Errorf("github source requires owner and repo")
	}
	if len(privateKey) == 0 {
		return nil, fmt.Errorf("github source requires private key")
	}
	return &GitHubSource{
		cfg:        cfg,
		privateKey: privateKey,
	}, nil
}

func (s *GitHubSource) Load(ctx context.Context) (*config.SourcedConfig, string, error) {
	appClient, err := githubprovider.NewClient(s.cfg.AppID, s.privateKey, s.cfg.Server)
	if err != nil {
		return nil, "", fmt.Errorf("creating github app client: %w", err)
	}
	gh, err := githubprovider.InstallationTokenClient(ctx, appClient, s.cfg.InstallationID)
	if err != nil {
		return nil, "", fmt.Errorf("github installation auth: %w", err)
	}

	ref := s.cfg.Ref
	if ref == "" {
		ref = "main"
	}

	revision, _, err := gh.Repositories.GetCommitSHA1(ctx, s.cfg.Owner, s.cfg.Repo, ref, "")
	if err != nil {
		return nil, "", fmt.Errorf("resolving ref %q: %w", ref, err)
	}

	log.Ctx(ctx).Debug().
		Str("owner", s.cfg.Owner).
		Str("repo", s.cfg.Repo).
		Str("ref", ref).
		Str("revision", revision).
		Msg("source: resolved git ref")

	tree, _, err := gh.Git.GetTree(ctx, s.cfg.Owner, s.cfg.Repo, revision, true)
	if err != nil {
		return nil, "", fmt.Errorf("fetching tree for ref %q: %w", ref, err)
	}
	if tree.GetTruncated() {
		return nil, "", fmt.Errorf("config tree is truncated, too many files in repo")
	}

	sourced := &config.SourcedConfig{}
	prefix := strings.TrimSuffix(s.cfg.Path, "/")
	if prefix != "" {
		prefix += "/"
	}

	files := 0
	for _, entry := range tree.Entries {
		if entry.GetType() != "blob" {
			continue
		}
		path := entry.GetPath()
		if !strings.HasPrefix(path, prefix) {
			continue
		}
		rel := strings.TrimPrefix(path, prefix)
		if !strings.HasSuffix(rel, ".yaml") && !strings.HasSuffix(rel, ".yml") {
			continue
		}

		content, err := s.fetchFile(ctx, gh, path, revision)
		if err != nil {
			return nil, "", fmt.Errorf("fetching file %q: %w", path, err)
		}
		if err := routeFile(sourced, rel, content); err != nil {
			return nil, "", fmt.Errorf("in %q: %w", path, err)
		}
		files++
	}

	log.Ctx(ctx).Debug().
		Str("revision", revision).
		Int("files", files).
		Msg("source: loaded config tree from github")
	return sourced, revision, nil
}

func (s *GitHubSource) fetchFile(ctx context.Context, gh *github.Client, path, ref string) ([]byte, error) {
	fileContent, _, _, err := gh.Repositories.GetContents(ctx, s.cfg.Owner, s.cfg.Repo, path,
		&github.RepositoryContentGetOptions{
			Ref: ref,
		})
	if err != nil {
		return nil, fmt.Errorf("fetching %q: %w", path, err)
	}
	decoded, err := fileContent.GetContent()
	if err != nil {
		return nil, fmt.Errorf("decoding %q: %w", path, err)
	}
	return []byte(decoded), nil
}

func routeFile(sourced *config.SourcedConfig, rel string, content []byte) error {
	switch {
	case strings.HasPrefix(rel, "issuers.d/"):
		var items []config.IssuerBlock
		if err := yaml.Unmarshal(content, &items); err != nil {
			return err
		}
		sourced.Issuers = append(sourced.Issuers, items...)
	case strings.HasPrefix(rel, "realms.d/"):
		var items []config.RealmBlock
		if err := yaml.Unmarshal(content, &items); err != nil {
			return err
		}
		sourced.Realms = append(sourced.Realms, items...)
	case strings.HasPrefix(rel, "rules.d/"):
		var items []core.Rule
		if err := yaml.Unmarshal(content, &items); err != nil {
			return err
		}
		sourced.Rules = append(sourced.Rules, items...)
	}
	// files outside the convention dirs are ignored
	return nil
}
