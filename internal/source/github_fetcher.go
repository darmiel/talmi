package source

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"

	"github.com/goccy/go-yaml"
	"github.com/google/go-github/v80/github"

	"github.com/darmiel/talmi/internal/config"
	"github.com/darmiel/talmi/internal/core"
	"github.com/darmiel/talmi/internal/ghapp"
	"github.com/darmiel/talmi/internal/logging"
)

type GitHubFetcher struct {
	cfg config.GitHubSourceConfig
}

func NewGitHubFetcher(cfg config.GitHubSourceConfig) (*GitHubFetcher, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid GitHub source config: %w", err)
	}
	return &GitHubFetcher{cfg: cfg}, nil
}

func (f *GitHubFetcher) Fetch(ctx context.Context, logger logging.InternalLogger) ([]core.Rule, error) {
	logger.Info("Starting GitHub source sync for repo %s/%s (ref: %s)", f.cfg.Owner, f.cfg.Repo, f.cfg.Ref)

	appClient, err := ghapp.NewClient(f.cfg.AppID, []byte(f.cfg.PrivateKey), f.cfg.ServerURL)
	if err != nil {
		return nil, fmt.Errorf("app auth failed: %w", err)
	}

	gh, err := ghapp.InstallationTokenClient(ctx, appClient, f.cfg.InstallationID)
	if err != nil {
		return nil, fmt.Errorf("installation auth failed: %w", err)
	}

	ref := f.cfg.Ref
	if ref == "" {
		ref = "main"
	}

	logger.Debug("Fetching tree for ref %s...", ref)
	tree, _, err := gh.Git.GetTree(ctx, f.cfg.Owner, f.cfg.Repo, ref, true)
	if err != nil {
		return nil, fmt.Errorf("get tree failed: %w", err)
	}

	var targetFiles []string
	for _, entry := range tree.Entries {
		path := entry.GetPath()

		if entry.GetType() != "blob" {
			continue
		}

		if f.cfg.Path != "" && !strings.HasPrefix(path, f.cfg.Path) {
			continue
		}

		if strings.HasSuffix(path, ".yaml") || strings.HasSuffix(path, ".yml") {
			targetFiles = append(targetFiles, path)
		}
	}
	if len(targetFiles) == 0 {
		logger.Warn("No policy files found in %s @ %s", f.cfg.Path, ref)
		return nil, nil
	}

	// sort targetFiles by name to allow for order-dependent rules
	slices.Sort(targetFiles)

	var (
		mu       sync.Mutex
		allRules []core.Rule
	)

	for i, path := range targetFiles {
		logger.Debug("Queuing download %d/%d: for %s", i+1, len(targetFiles), path)

		fileContent, _, _, err := gh.Repositories.GetContents(ctx, f.cfg.Owner, f.cfg.Repo, path, &github.RepositoryContentGetOptions{
			Ref: ref,
		})
		if err != nil {
			logger.Warn("Failed to download %s: %v", path, err)
			return nil, fmt.Errorf("download %s: %w", path, err)
		}

		content, err := fileContent.GetContent()
		if err != nil {
			logger.Warn("Failed to decode content of %s: %v", path, err)
			return nil, fmt.Errorf("decode content %s: %w", path, err)
		}

		var partialConfig config.Config
		if err := yaml.Unmarshal([]byte(content), &partialConfig); err != nil {
			logger.Error("Failed to parse YAML in %s: %v", path, err)
			return nil, fmt.Errorf("syntax error in %s: %w", path, err)
		}

		mu.Lock()
		allRules = append(allRules, partialConfig.Rules...)
		mu.Unlock()

		logger.Debug("Loaded %s, found %d rules", path, len(partialConfig.Rules))
	}

	logger.Info("Fetch complete. Total rules loaded: %d", len(allRules))
	return allRules, nil
}
