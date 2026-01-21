package core

import "context"

// Issuer is responsible for verifying upstream tokens.
// Implementations: OIDC Issuer, AWS IAM Issuer, Static/Stub Issuer.
type Issuer interface {
	// Name returns the identifier of this issuer (as used in config).
	Name() string

	// Verify takes a raw token string, validates it, and returns a Principal.
	Verify(ctx context.Context, token string) (*Principal, error)
}
