package store

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/darmiel/talmi/internal/core"
)

func lease(id, secret string, expiresAt time.Time) core.Lease {
	return core.Lease{
		ID:               id,
		PrincipalID:      "p",
		RevocationSecret: secret,
		Artifacts: []core.LeasedArtifact{
			{
				Provider: "gh",
				Realm:    "ghes-corp",
				Covers: []core.ResourceRequest{
					{
						Resource: "ghes-corp:acme/x",
						Actions:  []core.Action{"contents:read"},
					},
				},
				ExpiresAt: expiresAt,
				Metadata:  map[string]any{"k": "v"},
			},
		},
	}
}

func TestHashSecret(t *testing.T) {
	t.Parallel()
	is := assert.New(t)
	is.Equal(HashSecret("abc"), HashSecret("abc")) // deterministic
	is.NotEqual(HashSecret("abc"), HashSecret("abd"))
	is.NotEmpty(HashSecret(""))
}

func TestMemorySaveGet(t *testing.T) {
	t.Parallel()
	is := assert.New(t)
	must := require.New(t)
	s := NewMemoryLeaseStore()

	must.NoError(s.SaveLease(context.Background(), lease("l1", "secret", time.Now().Add(time.Hour))))

	got, err := s.GetLease(context.Background(), "l1")
	must.NoError(err)
	is.Equal("l1", got.ID)
	is.Empty(got.RevocationSecret, "plaintext secret must never be returned/stored")
	is.Len(got.Artifacts, 1)

	_, err = s.GetLease(context.Background(), "missing")
	is.ErrorIs(err, core.ErrLeaseNotFound)
}

func TestMemoryFindByRevocationSecret(t *testing.T) {
	t.Parallel()
	is := assert.New(t)
	s := NewMemoryLeaseStore()
	_ = s.SaveLease(context.Background(), lease("l1", "top-secret", time.Now().Add(time.Hour)))

	got, err := s.FindByRevocationSecret(context.Background(), "top-secret")
	is.NoError(err)
	is.Equal("l1", got.ID)

	_, err = s.FindByRevocationSecret(context.Background(), "wrong")
	is.ErrorIs(err, core.ErrLeaseNotFound)
}

func TestMemorySetLeaseRevoked(t *testing.T) {
	t.Parallel()
	is := assert.New(t)
	s := NewMemoryLeaseStore()
	_ = s.SaveLease(context.Background(), lease("l1", "s", time.Now().Add(time.Hour)))

	is.NoError(s.SetLeaseRevoked(context.Background(), "l1"))
	got, _ := s.GetLease(context.Background(), "l1")
	is.True(got.Artifacts[0].Revoked)

	is.ErrorIs(s.SetLeaseRevoked(context.Background(), "missing"), core.ErrLeaseNotFound)
}

func TestMemoryListActive(t *testing.T) {
	t.Parallel()
	is := assert.New(t)
	s := NewMemoryLeaseStore()
	_ = s.SaveLease(context.Background(), lease("active", "a", time.Now().Add(time.Hour)))
	_ = s.SaveLease(context.Background(), lease("expired", "b", time.Now().Add(-time.Hour)))
	revoked := lease("revoked", "c", time.Now().Add(time.Hour))
	_ = s.SaveLease(context.Background(), revoked)
	_ = s.SetLeaseRevoked(context.Background(), "revoked")

	active, err := s.ListActive(context.Background())
	is.NoError(err)
	require.Len(t, active, 1)
	is.Equal("active", active[0].ID)
}

func TestMemoryDeleteExpired(t *testing.T) {
	t.Parallel()
	is := assert.New(t)
	s := NewMemoryLeaseStore()
	_ = s.SaveLease(context.Background(), lease("active", "a", time.Now().Add(time.Hour)))
	_ = s.SaveLease(context.Background(), lease("expired", "b", time.Now().Add(-time.Hour)))

	n, err := s.DeleteExpired(context.Background())
	is.NoError(err)
	is.Equal(int64(1), n)

	_, err = s.GetLease(context.Background(), "expired")
	is.ErrorIs(err, core.ErrLeaseNotFound)
	// its revocation-secret index is cleaned up too
	_, err = s.FindByRevocationSecret(context.Background(), "b")
	is.ErrorIs(err, core.ErrLeaseNotFound)
	// the active one survives
	_, err = s.GetLease(context.Background(), "active")
	is.NoError(err)
}

func TestMemoryDefensiveCopy(t *testing.T) {
	t.Parallel()
	is := assert.New(t)
	s := NewMemoryLeaseStore()
	_ = s.SaveLease(context.Background(), lease("l1", "s", time.Now().Add(time.Hour)))

	got, _ := s.GetLease(context.Background(), "l1")
	got.Artifacts[0].Revoked = true // mutate the returned copy
	got.Artifacts[0].Metadata["k"] = "hacked"

	fresh, _ := s.GetLease(context.Background(), "l1")
	is.False(fresh.Artifacts[0].Revoked, "stored lease must be unaffected by caller mutation")
	is.Equal("v", fresh.Artifacts[0].Metadata["k"])
}
