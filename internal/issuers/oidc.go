package issuers

import (
	"context"
	"crypto"
	"encoding/json"
	"fmt"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"

	"github.com/darmiel/talmi/internal/config"
	"github.com/darmiel/talmi/internal/core"
	"github.com/darmiel/talmi/internal/secret"
)

var _ core.Issuer = (*OIDCIssuer)(nil)

type OIDCIssuer struct {
	name     string
	verifier *oidc.IDTokenVerifier
}

func NewOIDCIssuer(ctx context.Context, name string, cfg config.OIDCConfig) (*OIDCIssuer, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("oidc issuer %q: %w", name, err)
	}
	oidcCfg := &oidc.Config{ClientID: cfg.ClientID}

	switch {
	case cfg.JWKS != "":
		raw, err := secret.Resolve(cfg.JWKS)
		if err != nil {
			return nil, fmt.Errorf("resolving jwks for issuer %q: %w", name, err)
		}
		keys, err := parseJWKS(raw)
		if err != nil {
			return nil, fmt.Errorf("parsing jwks for issuer %q: %w", name, err)
		}
		return &OIDCIssuer{
			name:     name,
			verifier: oidc.NewVerifier(cfg.IssuerURL, &oidc.StaticKeySet{PublicKeys: keys}, oidcCfg),
		}, nil
	case cfg.JWKSURL != "":
		provider := (&oidc.ProviderConfig{
			IssuerURL: cfg.IssuerURL,
			JWKSURL:   cfg.JWKSURL,
		}).NewProvider(ctx)
		return &OIDCIssuer{
			name:     name,
			verifier: provider.Verifier(oidcCfg),
		}, nil
	default:
		provider, err := oidc.NewProvider(ctx, cfg.IssuerURL)
		if err != nil {
			return nil, fmt.Errorf("creating oidc provider for issuer %q: %w", name, err)
		}
		return &OIDCIssuer{
			name:     name,
			verifier: provider.Verifier(&oidc.Config{ClientID: cfg.ClientID}),
		}, nil
	}

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

	id := ""
	if sub, ok := claims["sub"]; ok {
		subStr, ok := sub.(string)
		if !ok {
			return nil, fmt.Errorf("invalid 'sub' claim type")
		}
		id = subStr
	}

	return &core.Principal{
		ID:         id,
		Issuer:     o.name,
		Attributes: claims,
	}, nil
}

// ExtractIssuerURL extracts the 'iss' claim from a JWT token string without verifying it.
func ExtractIssuerURL(tokenString string) (string, error) {
	parser := jwt.NewParser()
	token, _, err := parser.ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return "", fmt.Errorf("parsing token: %w", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", fmt.Errorf("invalid token claims")
	}

	issRaw, ok := claims["iss"]
	if !ok {
		return "", fmt.Errorf("token missing 'iss' claim")
	}

	iss, ok := issRaw.(string)
	if !ok {
		return "", fmt.Errorf("invalid 'iss' claim type")
	}

	return iss, nil
}

// parseJWKS extracts the public keys from a JWKS JSON document.
func parseJWKS(raw []byte) ([]crypto.PublicKey, error) {
	var set jose.JSONWebKeySet
	if err := json.Unmarshal(raw, &set); err != nil {
		return nil, fmt.Errorf("parsing jwks: %w", err)
	}
	keys := make([]crypto.PublicKey, 0, len(set.Keys))
	for i := range set.Keys {
		if k := set.Keys[i].Key; k != nil {
			keys = append(keys, k)
		}
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("jwks contains no usable keys")
	}
	return keys, nil
}
