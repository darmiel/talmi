package core

// Capability describes what a single provider instance can serve.
// The resolver uses it for validation and least-privilege ranking.
type Capability struct {
	// Realm is the realm name this instance serves (e.g. ghes-corp).
	Realm string

	// Resources are the patterns this instance can serve - either discovered live (GitHub)
	// or declared statically.
	Resources []string

	// MaxActions is the ceiling of actions this instance can grant.
	MaxActions []Action
}

// MintPlan is a batch that a single token will satisfy. One provider instance may emit several plans
// for one request set.
type MintPlan struct {
	// Provider is the instance name that will mint this plan.
	Provider string

	// Realm is the realm this plan belongs to.
	Realm string

	// Covers is the public, auditable set of resources + actions this one token satisfies.
	// The audit layer depends only on this, not the internal provider state.
	Covers []ResourceRequest

	// Internal is some provider-specific state or data produced by Plan() and consumed
	// by Mint() (e.g. installation ID, resolved repo list, effective permissions).
	// Same round-trip pattern as TokenArtifact.internalRevocationID.
	Internal any `json:"-"`
}
