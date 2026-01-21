package store

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/darmiel/talmi/internal/core"
)

var _ core.TokenStore = (*InMemoryTokenStore)(nil)

type InMemoryTokenStore struct {
	mu     sync.RWMutex
	tokens []core.TokenMetadata
}

func NewInMemoryTokenStore() *InMemoryTokenStore {
	return &InMemoryTokenStore{
		tokens: make([]core.TokenMetadata, 0),
	}
}

func (s *InMemoryTokenStore) Save(_ context.Context, meta core.TokenMetadata) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.tokens = append(s.tokens, meta)
	return nil
}

func (s *InMemoryTokenStore) ListActive(_ context.Context) ([]core.TokenMetadata, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	activeTokens := make([]core.TokenMetadata, 0)
	now := time.Now()

	for _, t := range s.tokens {
		if !t.Revoked && t.ExpiresAt.After(now) {
			activeTokens = append(activeTokens, t)
		}
	}

	return activeTokens, nil
}

func (s *InMemoryTokenStore) DeleteExpired(_ context.Context) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	var active []core.TokenMetadata
	var deletedCount int64

	for _, t := range s.tokens {
		if t.ExpiresAt.After(now) {
			active = append(active, t)
		} else {
			deletedCount++
		}
	}

	s.tokens = active
	return deletedCount, nil
}

func (s *InMemoryTokenStore) FindByRevocationToken(
	_ context.Context,
	revocationToken string,
) (*core.TokenMetadata, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, t := range s.tokens {
		if t.RevocationToken == revocationToken {
			if time.Now().After(t.ExpiresAt) {
				return nil, fmt.Errorf("token expired")
			}
			return &t, nil
		}
	}

	return nil, fmt.Errorf("token not found")
}

func (s *InMemoryTokenStore) SetRevoked(ctx context.Context, correlationID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i, t := range s.tokens {
		if t.CorrelationID == correlationID {
			s.tokens[i].Revoked = true
			return nil
		}
	}

	return fmt.Errorf("token with correlation ID %s not found", correlationID)
}
