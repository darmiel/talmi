package ratelimit

import (
	"context"
	"errors"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRedisBackendAdmitCharge(t *testing.T) {
	t.Parallel()
	mr := miniredis.RunT(t)
	rc := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	b := NewRedisLimiter(rc)
	key := Key{Layer: "ip", ID: "1.2.3.4", Profile: Profile{Capacity: 3, RefillPerSec: 0}}
	for range 3 {
		d, err := b.Admit(context.Background(), key)
		require.NoError(t, err)
		require.True(t, d.Allowed)
		require.NoError(t, b.Charge(context.Background(), key, 1))
	}
	d, err := b.Admit(context.Background(), key)
	require.NoError(t, err)
	assert.False(t, d.Allowed)
}

// errBackend is a Limiter that always errors, to exercise the fallback wrapper.
type errBackend struct{}

func (errBackend) Admit(context.Context, Key) (Decision, error) {
	return Decision{}, errors.New("backend down")
}

func (errBackend) Charge(context.Context, Key, int) error {
	return errors.New("backend down")
}

func TestFallbackOnBackendError(t *testing.T) {
	t.Parallel()
	fb := NewFallback(errBackend{}, NewMemoryLimiter(MemoryOptions{}))
	key := Key{Layer: "ip", ID: "x", Profile: Profile{Capacity: 5}}
	d, err := fb.Admit(context.Background(), key)
	require.NoError(t, err, "fallback masks backend error")
	assert.True(t, d.Allowed)
	assert.Equal(t, int64(1), fb.FallbackCount())
}

func TestFallbackChargeCountsToo(t *testing.T) {
	t.Parallel()
	fb := NewFallback(errBackend{}, NewMemoryLimiter(MemoryOptions{}))
	key := Key{Layer: "ip", ID: "x", Profile: Profile{Capacity: 5}}
	require.NoError(t, fb.Charge(context.Background(), key, 1), "fallback masks charge error")
	assert.Equal(t, int64(1), fb.FallbackCount())
}
