package core

import (
	"context"
	"time"
)

// TokenMetadata represents the state of an issued token.
type TokenMetadata struct {
	// CorrelationID is the unique identifier for the token and ID of the request that created (requested) it.
	CorrelationID string `json:"correlation_id"`

	// PrincipalID is the unique identifier of the principal who owns this token.
	PrincipalID string `json:"principal_id"`

	// Provider is the name of the downstream provider for which this token was issued.
	Provider string `json:"provider"`

	// PolicyName is the name of the policy (i.e. rule) that authorized this token issuance.
	PolicyName string `json:"policy_name"`

	// IssuedAt is the time when the token was issued.
	IssuedAt time.Time `json:"issued_at"`

	// ExpiresAt is the expiration time of the issued token.
	// It is used to check if the token is "active".
	ExpiresAt time.Time `json:"expires_at"`

	// Revocable indicates whether this token can be revoked before its expiration.
	Revocable       bool   `json:"revocable"`
	Revoked         bool   `json:"revoked"`
	RevocationToken string `json:"-"`
	RevocationID    string `json:"-"`

	// Metadata contains extra metadata (like scope, installation_id for GitHub, ...)
	Metadata map[string]any `json:"metadata"`
}

// TokenStore manages the lifecycle of issued tokens.
type TokenStore interface {
	// Save records a new issued token
	Save(ctx context.Context, meta TokenMetadata) error

	// ListActive returns tokens that have not expired yet
	ListActive(ctx context.Context) ([]TokenMetadata, error)

	// DeleteExpired removes tokens from the underlying storage that have expired
	DeleteExpired(ctx context.Context) (int64, error)

	// FindByRevocationToken retrieves metadata for a token using its revocation token
	FindByRevocationToken(ctx context.Context, revocationToken string) (*TokenMetadata, error)

	// SetRevoked marks a token as revoked
	SetRevoked(ctx context.Context, correlationID string) error
}
