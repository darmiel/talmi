package providers

import (
	"context"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/mitchellh/mapstructure"

	"github.com/darmiel/talmi/internal/config"
	"github.com/darmiel/talmi/internal/core"
)

type TalmiJWTProviderConfig struct {
}

type TalmiJWTGrantConfig struct {
	// Roles to include in the minted JWT
	Roles []string `mapstructure:"roles"`
}

type TalmiJWTProvider struct {
	name       string
	signingKey []byte
}

func NewTalmiJWTProvider(cfg config.ProviderConfig, signingKey []byte) (*TalmiJWTProvider, error) {
	var conf TalmiJWTProviderConfig
	decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		Metadata: nil,
		Result:   &conf,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create decoder for github_app provider '%s': %w", cfg.Name, err)
	}
	if err := decoder.Decode(cfg.Config); err != nil {
		return nil, fmt.Errorf("failed to decode config for github_app provider '%s': %w", cfg.Name, err)
	}

	return &TalmiJWTProvider{
		name:       cfg.Name,
		signingKey: signingKey,
	}, nil
}

func (p *TalmiJWTProvider) Name() string {
	return p.name
}

func (p *TalmiJWTProvider) Mint(
	ctx context.Context,
	principal *core.Principal,
	grant core.Grant,
) (*core.TokenArtifact, error) {
	var grantConf TalmiJWTGrantConfig
	decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		Metadata: nil,
		Result:   &grantConf,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create decoder for talmi_jwt grant in provider '%s': %w", p.name, err)
	}
	if err := decoder.Decode(grant.Config); err != nil {
		return nil, fmt.Errorf("failed to decode config for talmi_jwt grant in provider '%s': %w", p.name, err)
	}

	now := time.Now()
	exp := now.Add(1 * time.Hour)

	claims := jwt.MapClaims{
		"iss":        "talmi-auth",
		"sub":        principal.ID,
		"iat":        now.Unix(),
		"exp":        exp.Unix(),
		"roles":      grantConf.Roles,
		"origin_iss": principal.Issuer,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString(p.signingKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign talmi_jwt token: %w", err)
	}

	return &core.TokenArtifact{
		Value:       signedToken,
		Fingerprint: CalculateFingerprinter(TalmiFingerprintType, signedToken),
		ExpiresAt:   exp,
		Metadata: map[string]any{
			"type": "talmi_session",
		},
	}, nil
}
