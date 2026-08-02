package store

import (
	"context"
	"maps"
	"slices"
	"sync"
	"time"

	"github.com/darmiel/talmi/internal/core"
)

var _ core.LeaseStore = (*MemoryLeaseStore)(nil)

type MemoryLeaseStore struct {
	mu     sync.RWMutex
	leases map[string]core.Lease
	byHash map[string]string // revocation hash -> lease ID
}

func NewMemoryLeaseStore() *MemoryLeaseStore {
	return &MemoryLeaseStore{
		leases: make(map[string]core.Lease),
		byHash: make(map[string]string),
	}
}

func (s *MemoryLeaseStore) Close() error {
	return nil
}

func (s *MemoryLeaseStore) SaveLease(_ context.Context, lease core.Lease) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	stored := cloneLease(lease)
	if lease.RevocationSecret != "" {
		s.byHash[HashSecret(lease.RevocationSecret)] = stored.ID
	}
	stored.RevocationSecret = "" // Do not store the secret itself
	s.leases[stored.ID] = stored
	return nil
}

func (s *MemoryLeaseStore) GetLease(_ context.Context, leaseID string) (*core.Lease, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	lease, ok := s.leases[leaseID]
	if !ok {
		return nil, core.ErrLeaseNotFound
	}
	return new(cloneLease(lease)), nil
}

func (s *MemoryLeaseStore) ListActive(_ context.Context) ([]core.Lease, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	now := time.Now()
	var active []core.Lease
	for _, lease := range s.leases {
		if leaseActive(lease, now) {
			active = append(active, cloneLease(lease))
		}
	}

	return active, nil
}

func (s *MemoryLeaseStore) FindByRevocationSecret(_ context.Context, secret string) (*core.Lease, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	leaseID, ok := s.byHash[HashSecret(secret)]
	if !ok {
		return nil, core.ErrLeaseNotFound
	}

	lease, ok := s.leases[leaseID]
	if !ok {
		return nil, core.ErrLeaseNotFound
	}
	return new(cloneLease(lease)), nil
}

func (s *MemoryLeaseStore) SetLeaseRevoked(_ context.Context, leaseID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	lease, ok := s.leases[leaseID]
	if !ok {
		return core.ErrLeaseNotFound
	}
	updated := cloneLease(lease)
	for i := range updated.Artifacts {
		updated.Artifacts[i].Revoked = true
	}
	s.leases[leaseID] = updated
	return nil
}

func (s *MemoryLeaseStore) DeleteExpired(_ context.Context) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	var deleted int64
	for id, lease := range s.leases {
		if !allExpired(lease, now) {
			continue
		}
		delete(s.leases, id)
		for hash, hid := range s.byHash {
			if hid == id {
				delete(s.byHash, hash)
			}
		}
		deleted++
	}
	return deleted, nil
}

func leaseActive(lease core.Lease, now time.Time) bool {
	for _, a := range lease.Artifacts {
		if !a.Revoked && a.ExpiresAt.After(now) {
			return true
		}
	}
	return false
}

func allExpired(lease core.Lease, now time.Time) bool {
	for _, a := range lease.Artifacts {
		if a.ExpiresAt.After(now) {
			return false
		}
	}
	return true
}

func cloneLease(lease core.Lease) core.Lease {
	clone := lease
	clone.PolicyNames = slices.Clone(lease.PolicyNames)
	clone.Artifacts = make([]core.LeasedArtifact, len(lease.Artifacts))
	for i, a := range lease.Artifacts {
		ca := a
		ca.Covers = cloneCovers(a.Covers)
		ca.Metadata = maps.Clone(a.Metadata)
		clone.Artifacts[i] = ca
	}
	return clone
}

func cloneCovers(covers []core.ResourceRequest) []core.ResourceRequest {
	out := make([]core.ResourceRequest, len(covers))
	for i, c := range covers {
		cc := c
		cc.Actions = slices.Clone(c.Actions)
		out[i] = cc
	}
	return out
}
