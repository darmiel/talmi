package core

import "time"

// Lease groups every artifact minted for a single request.
// It is the one hiandle for audit, revocation and cleanup.
type Lease struct {
	// ID is the correlation ID of the request that created this lease.
	ID string `json:"id"`

	// PrincipalID is the verified subject that requested the lease.
	PrincipalID string `json:"principal_id"`

	// Issuer is the name of the issuer that verified the principal.
	Issuer string `json:"issuer"`

	// PolicyNames are the rules whose union authorized this lease.
	PolicyNames []string `json:"policy_names"`

	// PolicyRevision is the config git SHA the decision was made against,
	// tying the lease back to a specific, reproducable policy version.
	PolicyRevision string `json:"policy_revision"`

	// CreatedAt is when the lease was issued.
	CreatedAt time.Time `json:"created_at"`

	// RevocationSecret is a secret that can be used to revoke this lease.
	// It revokes _every_ child artifact.
	RevocationSecret string `json:"-"`

	// Artifacts are the minted tokens that make up this lease.
	Artifacts []LeasedArtifact `json:"artifacts"`
}

// LeasedArtifact is the per-token record within a Lease.
type LeasedArtifact struct {
	// Provider is the instance that minted this artifact.
	Provider string `json:"provider"`

	// Realm is the realm this artifact belongs to.
	Realm string `json:"realm"`

	// Covers is the set of resources + actions this token satisfies.
	Covers []ResourceRequest `json:"covers"`

	// Fingerprint is the provider-specific identifier for downstream tracing.
	Fingerprint string `json:"fingerprint"`

	// ExpiresAt is when this specific token expires.
	ExpiresAt time.Time `json:"expires_at"`

	// Revocable indicates the provider supports revoking this token early.
	Revocable bool `json:"revocable"`

	// Revoked is set once the token has been revoked.
	Revoked bool `json:"revoked"`

	// RevocationID is the provider-internal handle used to revoke this token.
	RevocationID string `json:"revocation_id"`

	// Metadata holds provider extras (installation ID, permissions, ...).
	Metadata map[string]any `json:"metadata,omitempty"`
}
