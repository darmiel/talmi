package core

import (
	"context"
	"fmt"
)

var ErrLeaseNotFound = fmt.Errorf("lease not found")

// LeaseStore persists issued leases and their artifacts.
type LeaseStore interface {
	// SaveLease persists the given lease.
	SaveLease(ctx context.Context, lease Lease) error

	// GetLease returns a lease by its ID or ErrLeaseNotFound if not found.
	GetLease(ctx context.Context, leaseID string) (*Lease, error)

	// ListActive returns leases with at least one non-revoked and non-expired artifact.
	ListActive(ctx context.Context) ([]Lease, error)

	// FindByRevocationSecret returns the lease matching the secret, or ErrLeaseNotFound if not found.
	FindByRevocationSecret(ctx context.Context, secret string) (*Lease, error)

	// SetLeaseRevoked marks the lease and all its artifacts as revoked.
	SetLeaseRevoked(ctx context.Context, leaseID string) error

	// DeleteExpired removes leases where every artifact is expired or revoked.
	DeleteExpired(ctx context.Context) (int64, error)
}
