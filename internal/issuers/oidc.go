package issuers

import (
	"context"
	"fmt"

	"github.com/coreos/go-oidc/v3/oidc"

	"github.com/darmiel/talmi/internal/config"
	"github.com/darmiel/talmi/internal/core"
)

type OIDCIssuer struct {
	name     string
	provider *oidc.Provider
	verifier *oidc.IDTokenVerifier
}

func NewOIDCIssuer(ctx context.Context, cfg config.IssuerConfig) (*OIDCIssuer, error) {
	issuerURL, ok := cfg.Config["issuer_url"].(string)
	if !ok {
		return nil, fmt.Errorf("oidc issuer '%s' missing 'issuer_url'", cfg.Name)
	}
	// expected audience, currently required // TODO: for future maybe allow empty audience
	clientID, ok := cfg.Config["client_id"].(string)
	if !ok {
		return nil, fmt.Errorf("oidc issuer '%s' missing 'client_id'", cfg.Name)
	}

	provider, err := oidc.NewProvider(ctx, issuerURL)
	if err != nil {
		return nil, fmt.Errorf("creating oidc provider for issuer '%s': %w", cfg.Name, err)
	}

	verifierConfig := &oidc.Config{
		ClientID: clientID,
	}
	verifier := provider.Verifier(verifierConfig)

	return &OIDCIssuer{
		name:     cfg.Name,
		provider: provider,
		verifier: verifier,
	}, nil
}

func (o *OIDCIssuer) Name() string {
	return o.name
}

func (o *OIDCIssuer) Verify(ctx context.Context, token string) (*core.Principal, error) {
	idToken, err := o.verifier.Verify(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("oidc verification failed: %w", err)
	}

	var claims map[string]any
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("extracting oidc claims: %w", err)
	}

	// flatten the claims to string attributes
	attributes := make(map[string]string)
	for k, v := range claims {
		switch val := v.(type) {
		case string:
			attributes[k] = val
		case fmt.Stringer:
			attributes[k] = val.String()
		default:
			attributes[k] = fmt.Sprint(val)
		}
	}

	id := ""
	if sub, ok := attributes["sub"]; ok {
		id = sub
	}

	return &core.Principal{
		ID:         id,
		Issuer:     o.name,
		Attributes: attributes,
	}, nil
}
