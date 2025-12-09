package core

import (
	"context"
	"time"
)

// TokenMetadata represents the state of an issued token.
type TokenMetadata struct {
	// CorrelationID is the unique identifier for the token and ID of the request that created (requested) it.
	CorrelationID string

	// PrincipalID is the unique identifier of the principal who owns this token.
	PrincipalID string

	// Provider is the name of the downstream provider for which this token was issued.
	Provider string

	// ExpiresAt is the expiration time of the issued token.
	// It is used to check if the token is "active".
	ExpiresAt time.Time

	// IssuedAt is the time when the token was issued.
	IssuedAt time.Time

	// Metadata contains extra metadata (like scope, installation_id for GitHub, ...)
	Metadata map[string]any
}

// TokenStore manages the lifecycle of issued tokens.
type TokenStore interface {
	// Save records a new issued token
	Save(ctx context.Context, meta TokenMetadata) error

	// ListActive returns tokens that have not expired yet
	ListActive(ctx context.Context) ([]TokenMetadata, error)
}
