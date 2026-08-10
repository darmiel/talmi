package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/darmiel/talmi/internal/core"
	"github.com/darmiel/talmi/internal/store"
)

var _ core.LeaseStore = (*LeaseStore)(nil)

// LeaseStore is a PostgreSQL-backed implementation of core.LeaseStore.
type LeaseStore struct {
	pool *pgxpool.Pool
}

func New(pool *pgxpool.Pool) *LeaseStore {
	return &LeaseStore{
		pool: pool,
	}
}

// OpenLeaseStore opens a PostgreSQL-backed lease store.
func OpenLeaseStore(ctx context.Context, dsn string) (*LeaseStore, error) {
	pool, err := Connect(ctx, dsn)
	if err != nil {
		return nil, err
	}
	return New(pool), nil
}

// Close closes the lease store and releases its resources.
func (s *LeaseStore) Close() error {
	s.pool.Close()
	return nil
}

func (s *LeaseStore) SaveLease(ctx context.Context, lease core.Lease) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	hash := ""
	if lease.RevocationSecret != "" {
		hash = store.HashSecret(lease.RevocationSecret)
	}

	if _, err := tx.Exec(ctx, `
		INSERT INTO leases
			(id, principal_id, issuer, policy_names, policy_revision, created_at, revocation_secret_hash)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		lease.ID, lease.PrincipalID, lease.Issuer, lease.PolicyNames, lease.PolicyRevision,
		lease.CreatedAt, hash,
	); err != nil {
		return fmt.Errorf("inserting lease: %w", err)
	}

	for _, a := range lease.Artifacts {
		if _, err := tx.Exec(ctx, `
			INSERT INTO lease_artifacts
				(artifact_id, lease_id, provider, realm, covers, fingerprint,
				 expires_at, revocable, requires_token_for_revocation, revoked, revocation_id, metadata)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
			a.ArtifactID, lease.ID, a.Provider, a.Realm, a.Covers, a.Fingerprint,
			a.ExpiresAt, a.Revocable, a.RequiresTokenForRevocation, a.Revoked, a.RevocationID, a.Metadata,
		); err != nil {
			return fmt.Errorf("inserting artifact %s: %w", a.ArtifactID, err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit transaction: %w", err)
	}
	return nil
}

func (s *LeaseStore) GetLease(ctx context.Context, leaseID string) (*core.Lease, error) {
	lease, err := s.scanLease(s.pool.QueryRow(ctx, `
		SELECT id, principal_id, issuer, policy_names, policy_revision, created_at
		FROM leases WHERE id = $1`, leaseID))
	if err != nil {
		return nil, err
	}
	if lease.Artifacts, err = s.loadArtifacts(ctx, lease.ID); err != nil {
		return nil, err
	}
	return lease, nil
}

func (s *LeaseStore) FindByRevocationSecret(ctx context.Context, secret string) (*core.Lease, error) {
	if secret == "" {
		return nil, core.ErrLeaseNotFound
	}
	lease, err := s.scanLease(s.pool.QueryRow(ctx, `
		SELECT id, principal_id, issuer, policy_names, policy_revision, created_at
		FROM leases WHERE revocation_secret_hash = $1`, store.HashSecret(secret)))
	if err != nil {
		return nil, err
	}
	if lease.Artifacts, err = s.loadArtifacts(ctx, lease.ID); err != nil {
		return nil, err
	}
	return lease, nil
}

func (s *LeaseStore) ListActive(ctx context.Context) ([]core.Lease, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT DISTINCT l.id, l.principal_id, l.issuer, l.policy_names, l.policy_revision, l.created_at
		FROM leases l
		JOIN lease_artifacts a ON a.lease_id = l.id
		WHERE a.revoked = false AND a.expires_at > now()
		ORDER BY l.created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("querying active leases: %w", err)
	}
	defer rows.Close()

	var leases []core.Lease
	for rows.Next() {
		lease, err := s.scanLease(rows)
		if err != nil {
			return nil, err
		}
		leases = append(leases, *lease)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating active leases: %w", err)
	}

	for i := range leases {
		arts, err := s.loadArtifacts(ctx, leases[i].ID)
		if err != nil {
			return nil, err
		}
		leases[i].Artifacts = arts
	}

	return leases, nil
}

func (s *LeaseStore) SetLeaseRevoked(ctx context.Context, leaseID string) error {
	tag, err := s.pool.Exec(ctx, `UPDATE lease_artifacts SET revoked = true WHERE lease_id = $1`, leaseID)
	if err != nil {
		return fmt.Errorf("revoking lease %q: %w", leaseID, err)
	}
	if tag.RowsAffected() == 0 { // every lease has at least one artifact, so this means the lease doesn't exist
		return core.ErrLeaseNotFound
	}
	return nil
}

func (s *LeaseStore) SetArtifactRevoked(ctx context.Context, leaseID, artifactID string) error {
	tag, err := s.pool.Exec(ctx, `
	UPDATE lease_artifacts SET revoked = true
	WHERE lease_id = $1 AND artifact_id = $2`, leaseID, artifactID)
	if err != nil {
		return fmt.Errorf("revoking artifact %q in lease %q: %w", artifactID, leaseID, err)
	}
	if tag.RowsAffected() == 0 {
		return core.ErrLeaseNotFound
	}
	return nil
}

func (s *LeaseStore) DeleteExpired(ctx context.Context) (int64, error) {
	tag, err := s.pool.Exec(ctx, `
		DELETE FROM leases l
		WHERE NOT EXISTS (
			SELECT 1 FROM lease_artifacts a
			WHERE a.lease_id = l.id AND a.expires_at > now()
		)`)
	if err != nil {
		return 0, fmt.Errorf("deleting expired leases: %w", err)
	}
	return tag.RowsAffected(), nil
}

type row interface {
	Scan(dest ...any) error
}

func (s *LeaseStore) scanLease(r row) (*core.Lease, error) {
	var l core.Lease
	err := r.Scan(&l.ID, &l.PrincipalID, &l.Issuer, &l.PolicyNames, &l.PolicyRevision, &l.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, core.ErrLeaseNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("scanning lease: %w", err)
	}
	return &l, nil
}

func (s *LeaseStore) loadArtifacts(ctx context.Context, leaseID string) ([]core.LeasedArtifact, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT artifact_id, provider, realm, covers, fingerprint, expires_at,
    	revocable, requires_token_for_revocation, revoked, revocation_id, metadata
		FROM lease_artifacts WHERE lease_id = $1 ORDER BY artifact_id`, leaseID)
	if err != nil {
		return nil, fmt.Errorf("querying artifacts: %w", err)
	}
	defer rows.Close()

	var artifacts []core.LeasedArtifact
	for rows.Next() {
		var a core.LeasedArtifact
		if err := rows.Scan(
			&a.ArtifactID, &a.Provider, &a.Realm, &a.Covers, &a.Fingerprint, &a.ExpiresAt,
			&a.Revocable, &a.RequiresTokenForRevocation, &a.Revoked, &a.RevocationID, &a.Metadata,
		); err != nil {
			return nil, fmt.Errorf("scanning artifact: %w", err)
		}
		artifacts = append(artifacts, a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating artifacts: %w", err)
	}
	return artifacts, nil
}
