package issuers

import (
	"context"
	"fmt"

	"github.com/golang-jwt/jwt/v5"

	"github.com/darmiel/talmi/internal/config"
	"github.com/darmiel/talmi/internal/core"
)

var _ core.Issuer = (*TalmiSessionIssuer)(nil)

// TalmiSessionAudience is the aud claim of admin session tokens.
const TalmiSessionAudience = "talmi-session"

// TalmiSessionIssuer verifies Talmi-signed admin session JWTs.
type TalmiSessionIssuer struct {
	name string
	key  []byte
}

func NewTalmiSessionIssuer(cfg config.IssuerBlock, key []byte) (*TalmiSessionIssuer, error) {
	if len(key) == 0 {
		return nil, fmt.Errorf("talmi-session issuer %q requires a signing key", cfg.Name)
	}
	return &TalmiSessionIssuer{
		name: cfg.Name,
		key:  key,
	}, nil
}

func (i *TalmiSessionIssuer) Name() string {
	return i.name
}

func (i *TalmiSessionIssuer) Verify(_ context.Context, token string) (*core.Principal, error) {
	claims := jwt.MapClaims{}
	parsed, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method %v", token.Header["alg"])
		}
		return i.key, nil
	})
	if err != nil || !parsed.Valid {
		return nil, fmt.Errorf("invalid talmi session token: %w", err)
	}
	if aud, _ := claims["aud"].(string); aud != TalmiSessionAudience {
		return nil, fmt.Errorf("token is not a talmi session")
	}
	sub, _ := claims["sub"].(string)
	return &core.Principal{
		ID:         sub,
		Issuer:     i.name,
		Attributes: claims,
	}, nil
}
