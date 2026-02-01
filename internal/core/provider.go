package core

import "context"

type Provider interface {
	// Name returns the identifier of this provider (as used in config).
	Name() string
	SupportedKinds() []string
}

type TokenMinter interface {
	Provider

	// Mint creates a new access token based on the Principal and the Grant.
	Mint(ctx context.Context, principal *Principal, targets []Target, grant Grant) (*TokenArtifact, error)
}

type PermissionDownscoper interface {
	Provider

	// Downscope calculates the effective permissions.
	// It compares the 'requested' permissions against the 'allowed' (granted) permissions.
	// Implementation is entirely provider-specific.
	Downscope(allowed, requested map[string]string) (map[string]string, error)
}

type TokenRevoker interface {
	Provider

	Revoke(ctx context.Context, revocationID, tokenVal string) error
}
