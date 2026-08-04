package issuers

import (
	"context"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/darmiel/talmi/internal/config"
	"github.com/darmiel/talmi/internal/core"
)

var _ core.Issuer = (*TalmiSessionIssuer)(nil)

// TalmiSessionAudience is the aud claim of admin session tokens.
const TalmiSessionAudience = "talmi-session"

// TalmiSessionIssuer verifies Talmi-signed admin session JWTs.
type TalmiSessionIssuer struct {
	name   string
	signer *SessionSigner
}

func NewTalmiSessionIssuer(cfg config.IssuerBlock, signer *SessionSigner) (*TalmiSessionIssuer, error) {
	if signer == nil {
		return nil, fmt.Errorf("talmi-session issuer %q requires a signing key", cfg.Name)
	}
	return &TalmiSessionIssuer{
		name:   cfg.Name,
		signer: signer,
	}, nil
}

func (i *TalmiSessionIssuer) Name() string {
	return i.name
}

func (i *TalmiSessionIssuer) Verify(_ context.Context, token string) (*core.Principal, error) {
	claims := jwt.MapClaims{}
	parsed, err := jwt.ParseWithClaims(token, claims, i.signer.keyfunc)
	if err != nil || !parsed.Valid {
		return nil, fmt.Errorf("invalid talmi session token: %w", err)
	}
	if aud, _ := claims["aud"].(string); aud != TalmiSessionAudience {
		return nil, fmt.Errorf("token is not a talmi session")
	}
	// restore information from claims
	sub, _ := claims["sub"].(string)
	issuer := i.name
	if oi, ok := claims["origin_iss"].(string); ok {
		issuer = oi
	}
	attrs, _ := claims["attrs"].(map[string]any)
	if attrs == nil {
		attrs = make(map[string]any)
	}
	return &core.Principal{
		ID:         sub,
		Issuer:     issuer,
		Attributes: attrs,
	}, nil
}

// IssueSession mints a Talmi admin session JWT for the given principal.
func IssueSession(signer *SessionSigner, principal *core.Principal, ttl time.Duration) (string, time.Time, error) {
	now := time.Now()
	exp := now.Add(ttl)
	claims := jwt.MapClaims{
		"iss":        "talmi-auth",
		"aud":        TalmiSessionAudience,
		"sub":        principal.ID,
		"origin_iss": principal.Issuer,
		"attrs":      principal.Attributes,
		"iat":        now.Unix(),
		"exp":        exp.Unix(),
	}
	signed, err := signer.Sign(claims)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("signing talmi session token: %w", err)
	}
	return signed, exp, nil
}
