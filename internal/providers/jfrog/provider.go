package jfrog

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/mitchellh/mapstructure"
	"github.com/rs/zerolog/log"

	"github.com/darmiel/talmi/internal/config"
	"github.com/darmiel/talmi/internal/core"
)

const (
	Type        = "artifactory"
	DefaultKind = "artifactory"
)

var info = core.ProviderInfo{
	Type:    Type,
	Version: "v1",
}

var (
	_ core.TokenMinter  = (*Provider)(nil)
	_ core.TokenRevoker = (*Provider)(nil)
)

type Provider struct {
	name           string
	serverBaseURL  string
	token          string
	httpClient     *http.Client
	supportedKinds []string
}

type ProviderConfig struct {
	Server string `mapstructure:"server"`
	Token  string `mapstructure:"token"`
}

type GrantConfig struct {
	Scope             string `mapstructure:"scope"`
	ExpiryInSeconds   int64  `mapstructure:"expiry_in_seconds"`
	DescriptionSuffix string `mapstructure:"description,omitempty"`
	Audience          string `mapstructure:"audience,omitempty"`
}

func New(name, serverBaseURL, token string, kinds []string) (*Provider, error) {
	if len(kinds) == 0 {
		kinds = []string{DefaultKind}
	}
	normalizedServerBaseURL := strings.TrimRight(serverBaseURL, "/")
	if normalizedServerBaseURL == "" {
		return nil, fmt.Errorf("server base URL cannot be empty for %s provider '%s'", Type, name)
	}
	if token == "" {
		return nil, fmt.Errorf("token cannot be empty for %s provider '%s'", Type, name)
	}
	return &Provider{
		name:           name,
		serverBaseURL:  normalizedServerBaseURL,
		token:          token,
		httpClient:     http.DefaultClient,
		supportedKinds: kinds,
	}, nil
}

func NewFromConfig(cfg config.ProviderConfig) (*Provider, error) {
	var conf ProviderConfig

	decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		Metadata: nil,
		Result:   &conf,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create decoder for %s provider '%s': %w", Type, cfg.Name, err)
	}
	if err := decoder.Decode(cfg.Config); err != nil {
		return nil, fmt.Errorf("failed to decode config for %s provider '%s': %w", Type, cfg.Name, err)
	}

	return New(cfg.Name, conf.Server, conf.Token, cfg.Kinds)
}

func (g *Provider) Name() string {
	return g.name
}

func (g *Provider) SupportedKinds() []string {
	return g.supportedKinds
}

func (g *Provider) Mint(
	ctx context.Context,
	principal *core.Principal,
	_ []core.Target,
	grant core.Grant,
) (*core.TokenArtifact, error) {
	logger := log.Ctx(ctx)
	logger.Debug().Msgf("JFrogArtifactoryProvider Mint called for principal ID: %s", principal.ID)

	var grantConf GrantConfig
	decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		Metadata: nil,
		Result:   &grantConf,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create decoder for jfrog-artifactory grant config: %w", err)
	}
	if err := decoder.Decode(grant.Config); err != nil {
		return nil, fmt.Errorf("failed to decode jfrog-artifactory grant config: %w", err)
	}

	logger.Info().
		Str("provider", g.name).
		Str("scope", grantConf.Scope).
		Int64("expires_in", grantConf.ExpiryInSeconds).
		Str("audience", grantConf.Audience).
		Msg("minting JFrog Artifactory installation token")

	description := fmt.Sprintf("[talmi for %s]", principal.ID)
	if grantConf.DescriptionSuffix != "" {
		description += " " + grantConf.DescriptionSuffix
	}

	requestExpiresIn := grantConf.ExpiryInSeconds
	if requestExpiresIn <= 0 {
		// Talmi should be used for ephemeral tokens, so we set a default expiry of 1 hour
		requestExpiresIn = 3600
	}

	resp, err := g.CreateToken(ctx, principal.ID, &CreateTokenRequest{
		Scope:                 grantConf.Scope,
		ExpiresIn:             requestExpiresIn,
		Refreshable:           false,
		Description:           description,
		Audience:              grantConf.Audience,
		IncludeReferenceToken: false,
	})
	if err != nil {
		return nil, fmt.Errorf("creating JFrog Artifactory token: %w", err)
	}

	logger.Debug().Msgf("Minted JFrog Artifactory token ID: %s", resp.TokenID)

	responseExpiresIn := resp.ExpiresIn
	if responseExpiresIn <= 0 {
		// this token looks to be permanent, so we set a far future expiry time
		responseExpiresIn = 60 * 60 * 24 * 365 * 100
	}

	artifact := &core.TokenArtifact{
		Value:       resp.AccessToken,
		Fingerprint: resp.TokenID, // just use the token ID as the fingerprint, TODO: check if this is sufficient
		ExpiresAt:   time.Now().Add(time.Duration(responseExpiresIn) * time.Second),
		Provider:    info,
		Metadata: map[string]any{
			"token_id":   resp.TokenID,
			"token_type": resp.TokenType,
			"scope":      resp.Scope,
			"username":   resp.Username,
		},
	}
	artifact.SetRevocationID(resp.TokenID) // JFrog tokens can be revoked by their token ID

	return artifact, nil
}

func (g *Provider) Revoke(ctx context.Context, revocationID, tokenVal string) error {
	logger := log.Ctx(ctx)
	logger.Debug().Msgf("JFrogArtifactoryProvider Revoke called for revocation ID: %s", revocationID)

	if revocationID == "" {
		return fmt.Errorf("cannot revoke jfrog-artifactory token: revocation ID is empty")
	}

	if err := g.RevokeToken(ctx, revocationID); err != nil {
		return fmt.Errorf("deleting jfrog-artifactory token ID %s: %w", revocationID, err)
	}

	return nil
}
