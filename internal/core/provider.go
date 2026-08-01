package core

import "context"

type Provider interface {
	// Name returns the identifier of this provider (as used in config).
	Name() string
}

// ResourceProvider is a provider instance (app or account) that plans and mints tokens for resources in a single realm.
type ResourceProvider interface {
	Provider

	// Realm is the realm name this instance serves, e.g. "ghes-corp".
	Realm() string

	// Capabilities reports what this instance can serve, for validation and least-privilege ranking.
	Capabilities(ctx context.Context) (Capability, error)

	// Plan groups requests which the resolver has already determined this instance can serve.
	Plan(ctx context.Context, requests []ResourceRequest) ([]MintPlan, error)

	// Mint issues the token for a single plan produced by Plan.
	Mint(ctx context.Context, principal *Principal, plan MintPlan) (*TokenArtifact, error)
}

type TokenRevoker interface {
	Provider

	Revoke(ctx context.Context, revocationID, tokenVal string) error
}
