package core

import "time"

// TokenArtifact is the result of a successful Mint operation.
type TokenArtifact struct {
	// Value is the actual secret/token string (e.g., the GitHub Installation Token).
	Value string `json:"value"`

	// Fingerprint is the provider-specific identifier for tracability.
	Fingerprint string `json:"fingerprint"`

	// ExpiresAt indicates when this token becomes invalid.
	ExpiresAt time.Time `json:"expires_at"`

	// RevocationToken is a random string given to the client.
	// It can be used to revoke a token issued by Talmi.
	// This may be empty, depending on if the provider supports revoking tokens.
	RevocationToken string `json:"revocation_token"`

	// internal state passed from Minter to Service.
	// It holds the Provider-specific ID needed for revocation (e.g. a token ID).
	internalRevocationID string

	// Provider contains information about the issuing provider.
	Provider ProviderInfo `json:"provider"`

	// Metadata contains extra information (e.g., "git_user": "x-access-token").
	Metadata map[string]any `json:"metadata,omitempty"`
}

// helpers for providers to set the internal ID during Minting,
// only used for internal usage.

func (t *TokenArtifact) SetRevocationID(id string) {
	t.internalRevocationID = id
}

func (t *TokenArtifact) RevocationID() string {
	return t.internalRevocationID
}
