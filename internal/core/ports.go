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

// Provider is responsible for minting downstream tokens.
// Implementations: GitHub App Provider, Vault Provider, Stub Provider.
type Provider interface {
	// Name returns the identifier of this provider (as used in config).
	Name() string

	// Mint creates a new access token based on the Principal and the Grant.
	Mint(ctx context.Context, principal *Principal, grant Grant) (*TokenArtifact, error)
}
