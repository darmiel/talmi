package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/go-github/v80/github"
	"github.com/mitchellh/mapstructure"
	"github.com/rs/zerolog/log"

	"github.com/darmiel/talmi/internal/api/middleware"
	"github.com/darmiel/talmi/internal/audit"
	"github.com/darmiel/talmi/internal/config"
	"github.com/darmiel/talmi/internal/core"
)

type GitHubAppProviderConfig struct {
	AppID          int64  `mapstructure:"app_id"`
	PrivateKey     string `mapstructure:"private_key"`
	PrivateKeyFile string `mapstructure:"private_key_path"`

	// Optional: GitHub Enterprise server URL. Defaults to https://api.github.com
	ServerBaseURL string `mapstructure:"server"`

	// AllowAllRepositories has to be set to true in order to allow empty repositories list in grants.
	// This is just a safety mechanism to avoid unintentional wide access.
	// This does NOT mean that all repositories are granted, but rather that the provider allows it.
	AllowAllRepositories bool `mapstructure:"allow_all_repositories"`

	// AllowAllPermissions has to be set to true in order to allow empty permissions in grants.
	// This is just a safety mechanism to avoid unintentional wide access.
	// This does NOT mean that all permissions are granted, but rather that the provider allows it.
	AllowAllPermissions bool `mapstructure:"allow_all_permissions"`
}

type GitHubAppGrantConfig struct {
	// Optional: explicitly define which installation to use. Bypasses owner lookup.
	// You have to specify ONE OF InstallationID OR Owner.
	InstallationID *int64 `mapstructure:"installation_id"`

	// Optional: Lookup installation by owner (user/org)
	// You have to specify ONE OF InstallationID OR Owner.
	Owner string `mapstructure:"owner"`

	// Optional: Limit access to specific repositories.
	// If empty, and scope is not limited, all repositories are accessible.
	Repositories []string `mapstructure:"repositories"`
}

// GitHubAppProvider implements core.Provider by minting GitHub App installation tokens.
// It supports GitHub Cloud and GitHub Enterprise.
// The provider requires configuration of the App ID and the private key.
// Grants must specify either the installation ID or the owner (user/org) where the app is installed.
// Additionally, grants can limit the token to specific repositories and permissions.
type GitHubAppProvider struct {
	name       string
	appID      int64
	privateKey []byte

	serverBaseURL string

	allowAllRepositories bool
	allowAllPermissions  bool
}

// NewGitHubAppProvider creates a new GitHubAppProvider from the given config.
func NewGitHubAppProvider(cfg config.ProviderConfig) (*GitHubAppProvider, error) {
	var conf GitHubAppProviderConfig

	decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		Metadata: nil,
		Result:   &conf,
		//WeaklyTypedInput: true, // TODO: check if this is required :)
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create decoder for github_app provider '%s': %w", cfg.Name, err)
	}
	if err := decoder.Decode(cfg.Config); err != nil {
		return nil, fmt.Errorf("failed to decode config for github_app provider '%s': %w", cfg.Name, err)
	}

	// load the key bytes
	var keyBytes []byte
	if conf.PrivateKey != "" {
		keyBytes = []byte(conf.PrivateKey)
	} else if conf.PrivateKeyFile != "" {
		contents, err := os.ReadFile(conf.PrivateKeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read private key file for github_app provider '%s': %w", cfg.Name, err)
		}
		keyBytes = contents
	} else {
		return nil, fmt.Errorf("github_app provider '%s' missing 'private_key' or 'private_key_path'", cfg.Name)
	}

	return &GitHubAppProvider{
		name:                 cfg.Name,
		appID:                conf.AppID,
		privateKey:           keyBytes,
		serverBaseURL:        conf.ServerBaseURL,
		allowAllRepositories: conf.AllowAllRepositories,
		allowAllPermissions:  conf.AllowAllPermissions,
	}, nil
}

func (g *GitHubAppProvider) Name() string {
	return g.name
}

func (g *GitHubAppProvider) Mint(
	ctx context.Context,
	principal *core.Principal,
	grant core.Grant,
) (*core.TokenArtifact, error) {
	logger := log.Ctx(ctx)
	logger.Debug().Msgf("GitHubAppProvider Mint called for principal ID: %s", principal.ID)

	var grantConf GitHubAppGrantConfig
	decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		Metadata: nil,
		Result:   &grantConf,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create decoder for github_app grant config: %w", err)
	}
	if err := decoder.Decode(grant.Config); err != nil {
		return nil, fmt.Errorf("failed to decode github_app grant config: %w", err)
	}

	// authenticate as the app
	appClient, err := g.createAppClient(ctx, principal.ID, grant.Provider)
	if err != nil {
		return nil, fmt.Errorf("creating github app client: %w", err)
	}
	log.Debug().Msgf("Using User-Agent: %s", appClient.UserAgent)

	// determine installation ID
	var installationID int64
	if grantConf.InstallationID != nil && *grantConf.InstallationID != 0 {
		installationID = *grantConf.InstallationID
	} else if grantConf.Owner != "" {
		// find installation by owner
		// the most common case is that the app is installed in an org
		installation, _, err := appClient.Apps.FindOrganizationInstallation(ctx, grantConf.Owner)
		if err != nil {
			var err2 error
			installation, _, err2 = appClient.Apps.FindUserInstallation(ctx, grantConf.Owner)
			if err2 != nil {
				return nil, fmt.Errorf("could not find app installation for owner '%s': %w / %v", grantConf.Owner, err, err2)
			}
		}
		installationID = installation.GetID()
	} else {
		return nil, fmt.Errorf("github_app grant config must specify either 'installation_id' or 'owner'")
	}
	logger.Debug().Msgf("retrieved installation ID: %d", installationID)

	// limit the token to a set of permissions
	var ghPerms github.InstallationPermissions
	if len(grant.Permissions) > 0 {
		// use JSON to unmarshal the permissions to InstallationPermissions.
		// this is a bit scuffed, but works for now :)
		jsonBytes, err := json.Marshal(grant.Permissions)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal permissions: %w", err)
		}
		if err := json.Unmarshal(jsonBytes, &ghPerms); err != nil {
			return nil, fmt.Errorf("failed to unmarshal permissions to github installation permissions: %w", err)
		}
	} else if !g.allowAllPermissions {
		// we just CANNOT accept returning a token with all permissions,
		// that's a fire hazard.
		return nil, fmt.Errorf("github_app grant must specify permissions or the provider must allow all permissions")
	}

	// now we can request the installation token
	opts := &github.InstallationTokenOptions{
		Permissions: &ghPerms,
	}

	// limit the token scope to a few repositories if specified
	if len(grantConf.Repositories) > 0 {
		opts.Repositories = grantConf.Repositories
	} else if !g.allowAllRepositories {
		return nil, fmt.Errorf("github_app grant must specify repositories or the provider must allow all repositories")
	}

	logger.Info().
		Str("provider", g.name).
		Int64("installation_id", installationID).
		Int("repos_count", len(opts.Repositories)).
		Interface("permissions", ghPerms).
		Msg("minting GitHub App installation token")

	// mint the token
	token, _, err := appClient.Apps.CreateInstallationToken(ctx, installationID, opts)
	if err != nil {
		return nil, fmt.Errorf("creating installation token for installation ID %d: %w", installationID, err)
	}
	logger.Debug().Msgf("Minted token expiring at %s", token.GetExpiresAt().Time.String())

	tok := token.GetToken()

	return &core.TokenArtifact{
		Value:       tok,
		ExpiresAt:   token.GetExpiresAt().Time,
		Fingerprint: CalculateFingerprinter(GitHubFingerprintType, tok),
		Metadata: map[string]any{
			"installation": installationID,
			"repositories": opts.Repositories,
			"permissions":  token.GetPermissions(),
		},
	}, nil
}

func (g *GitHubAppProvider) createAppClient(ctx context.Context, principalID, provider string) (*github.Client, error) {
	correlationID := middleware.CorrelationCtx(ctx)

	key, err := jwt.ParseRSAPrivateKeyFromPEM(g.privateKey)
	if err != nil {
		return nil, fmt.Errorf("parsing github app private key: %w", err)
	}
	now := time.Now()
	claims := jwt.MapClaims{
		"iat": now.Unix(),
		"exp": now.Add(9 * time.Minute).Unix(),
		"iss": g.appID,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signedToken, err := token.SignedString(key)
	if err != nil {
		return nil, fmt.Errorf("signing github app jwt: %w", err)
	}

	client := github.NewClient(nil).
		WithAuthToken(signedToken)

	if g.serverBaseURL != "" {
		// we don't interact with uploads, so just use a dummy URL here.
		client, err = client.WithEnterpriseURLs(g.serverBaseURL, "https://github.com/api/uploads")
		if err != nil {
			return nil, fmt.Errorf("creating github enterprise client: %w", err)
		}
	}

	// set user agent for auditing
	client.UserAgent = audit.CreateUserAgent(correlationID, principalID, provider)

	return client, nil
}
