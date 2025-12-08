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

	"github.com/darmiel/talmi/internal/config"
	"github.com/darmiel/talmi/internal/core"
)

const (
	defaultServerBaseURL = "https://api.github.com"
)

type GitHubAppProviderConfig struct {
	AppID          int64  `mapstructure:"app_id"`
	PrivateKey     string `mapstructure:"private_key"`
	PrivateKeyFile string `mapstructure:"private_key_path"`

	// Optional: GitHub Enterprise server URL. Defaults to https://api.github.com
	ServerBaseURL string `mapstructure:"server_base_url"`

	// Optional: GitHub Enterprise upload URL. Defaults to https://uploads.github.com
	ServerUploadURL string `mapstructure:"server_upload_url"`

	// AllowAllRepositories has to be set to true in order to allow empty repositories list in grants.
	// This is just a safety mechanism to avoid unintentional wide access.
	// This does NOT mean that all repositories are granted, but rather that the provider allows it.
	AllowAllRepositories bool `mapstructure:"allow_all_repositories"`

	// AllowAllPermissions has to be set to true in order to allow empty permissions in grants.
	// This is just a safety mechanism to avoid unintentional wide access.
	// This does NOT mean that all permissions are granted, but rather that the provider allows it.
	AllowAllPermissions bool `mapstructure:"allow_all_permissions"`
}

type GrantConfig struct {
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

	serverBaseURL   string
	serverUploadURL string // TODO: required?

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
		serverUploadURL:      conf.ServerUploadURL,
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
	log.Info().Msgf("GitHubAppProvider Mint called for principal ID: %s", principal.ID)

	var grantConf GrantConfig
	decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		Metadata: nil,
		Result:   &grantConf,
		//WeaklyTypedInput: true, // TODO: check if this is required :)
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create decoder for github_app grant config: %w", err)
	}
	if err := decoder.Decode(grant.Config); err != nil {
		return nil, fmt.Errorf("failed to decode github_app grant config: %w", err)
	}

	// authenticate as the app
	appClient, err := g.createAppClient()
	if err != nil {
		return nil, fmt.Errorf("creating github app client: %w", err)
	}
	log.Debug().Msg("Created GitHub App client")

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
	log.Debug().Msgf("Determined installation ID: %d", installationID)

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

	log.Info().
		Str("provider", g.name).
		Int64("installation_id", installationID).
		Int("repos_count", len(opts.Repositories)).
		Interface("permissions", ghPerms).
		Msg("Minting GitHub App installation token")

	// mint the token
	token, _, err := appClient.Apps.CreateInstallationToken(ctx, installationID, opts)
	if err != nil {
		return nil, fmt.Errorf("creating installation token for installation ID %d: %w", installationID, err)
	}
	log.Debug().Msgf("Minted token expiring at %s", token.GetExpiresAt().Time.String())

	return &core.TokenArtifact{
		Value:     token.GetToken(),
		ExpiresAt: token.GetExpiresAt().Time,
		Metadata: map[string]any{
			"scm":             "github",
			"installation_id": installationID,
			"repos_count":     len(opts.Repositories),
			"permissions":     token.GetPermissions(),
		},
	}, nil
}

func (g *GitHubAppProvider) createAppClient() (*github.Client, error) {
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
	log.Debug().Str("token", signedToken).
		Msgf("Created signed JWT for GitHub App authentication")

	client := github.NewClient(nil).
		WithAuthToken(signedToken)

	if g.serverBaseURL != "" || g.serverUploadURL != "" {
		log.Debug().Msgf("Creating GitHub Enterprise client with BaseURL: %s, UploadURL: %s", g.serverBaseURL, g.serverUploadURL)
		client, err = client.WithEnterpriseURLs(g.serverBaseURL, g.serverUploadURL)
		if err != nil {
			return nil, fmt.Errorf("creating github enterprise client: %w", err)
		}
	}

	return client, nil
}
