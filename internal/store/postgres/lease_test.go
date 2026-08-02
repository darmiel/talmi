//go:build integration

package postgres

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/darmiel/talmi/internal/core"
)

func newTestStore(t *testing.T) *LeaseStore {
	t.Helper()
	dsn := os.Getenv("TALMI_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TALMI_TEST_DATABASE_URL to run postgres integration tests (schema must be migrated)")
	}
	pool, err := Connect(context.Background(), dsn)
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	_, err = pool.Exec(context.Background(), `TRUNCATE leases CASCADE`)
	require.NoError(t, err)
	return New(pool)
}

func sampleLease(id, secret string, expiresAt time.Time) core.Lease {
	return core.Lease{
		ID:               id,
		PrincipalID:      "pipeline/deploy",
		Issuer:           "concourse",
		PolicyNames:      []string{"read", "write-svc"},
		PolicyRevision:   "abc123",
		CreatedAt:        time.Now().UTC().Truncate(time.Second),
		RevocationSecret: secret,
		Artifacts: []core.LeasedArtifact{
			{
				Provider: "gh-deploy",
				Realm:    "ghes-corp",
				Covers: []core.ResourceRequest{
					{
						Resource: "ghes-corp:acme/svc-a",
						Actions:  []core.Action{"contents:write"},
					},
				},
				Fingerprint:  "fp-1",
				ExpiresAt:    expiresAt,
				Revocable:    true,
				RevocationID: "github-installation-111",
				Metadata:     map[string]any{"installation": float64(111)},
			},
		},
	}
}

func TestPostgresRoundTrip(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	in := sampleLease("l1", "secret", time.Now().Add(time.Hour))

	require.NoError(t, s.SaveLease(ctx, in))

	got, err := s.GetLease(ctx, "l1")
	require.NoError(t, err)
	assert.Equal(t, in.ID, got.ID)
	assert.Equal(t, in.PolicyNames, got.PolicyNames)
	assert.Empty(t, got.RevocationSecret) // never returned
	require.Len(t, got.Artifacts, 1)
	assert.Equal(t, in.Artifacts[0].Covers, got.Artifacts[0].Covers) // jsonb round-trip
	assert.Equal(t, float64(111), got.Artifacts[0].Metadata["installation"])

	_, err = s.GetLease(ctx, "missing")
	assert.ErrorIs(t, err, core.ErrLeaseNotFound)
}

func TestPostgresRevocationAndActive(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	require.NoError(t, s.SaveLease(ctx, sampleLease("active", "sec-a", time.Now().Add(time.Hour))))

	found, err := s.FindByRevocationSecret(ctx, "sec-a")
	require.NoError(t, err)
	assert.Equal(t, "active", found.ID)

	_, err = s.FindByRevocationSecret(ctx, "wrong")
	assert.ErrorIs(t, err, core.ErrLeaseNotFound)

	active, err := s.ListActive(ctx)
	require.NoError(t, err)
	assert.Len(t, active, 1)

	require.NoError(t, s.SetLeaseRevoked(ctx, "active"))
	active, err = s.ListActive(ctx)
	require.NoError(t, err)
	assert.Empty(t, active, "revoked lease must not be active")

	assert.ErrorIs(t, s.SetLeaseRevoked(ctx, "missing"), core.ErrLeaseNotFound)
}

func TestPostgresDeleteExpired(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	require.NoError(t, s.SaveLease(ctx, sampleLease("live", "a", time.Now().Add(time.Hour))))
	require.NoError(t, s.SaveLease(ctx, sampleLease("dead", "b", time.Now().Add(-time.Hour))))

	n, err := s.DeleteExpired(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(1), n)

	_, err = s.GetLease(ctx, "dead")
	assert.ErrorIs(t, err, core.ErrLeaseNotFound)
	_, err = s.GetLease(ctx, "live")
	assert.NoError(t, err)
}
