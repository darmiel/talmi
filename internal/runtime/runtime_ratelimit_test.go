package runtime

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/darmiel/talmi/internal/config"
	"github.com/darmiel/talmi/internal/ratelimit"
)

func TestBuildLimiter(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	// a tiny non-refilling bucket so we can drain it deterministically
	key := ratelimit.Key{Layer: "ip", ID: "x", Profile: ratelimit.Profile{Capacity: 2, RefillPerSec: 0}}

	t.Run("nil config yields a no-op limiter that always admits", func(t *testing.T) {
		t.Parallel()
		lim, _, err := buildRateLimiter(nil)
		require.NoError(t, err)
		require.NotNil(t, lim)

		require.NoError(t, lim.Charge(ctx, key, 1000)) // even a huge charge is a no-op
		d, err := lim.Admit(ctx, key)
		require.NoError(t, err)
		assert.True(t, d.Allowed, "no-op limiter always admits")
	})

	t.Run("disabled config yields a no-op limiter", func(t *testing.T) {
		t.Parallel()
		lim, _, err := buildRateLimiter(&config.RateLimitConfig{Enabled: false})
		require.NoError(t, err)
		require.NotNil(t, lim)

		require.NoError(t, lim.Charge(ctx, key, 1000))
		d, err := lim.Admit(ctx, key)
		require.NoError(t, err)
		assert.True(t, d.Allowed)
	})

	t.Run("enabled memory config enforces limits", func(t *testing.T) {
		t.Parallel()
		lim, rt, err := buildRateLimiter(&config.RateLimitConfig{
			Enabled:   true,
			Backend:   "memory",
			IP:        config.RateLimitProfile{Capacity: 60, RefillPerSec: 1},
			Principal: config.RateLimitProfile{Capacity: 120, RefillPerSec: 2},
		})
		require.NoError(t, err)
		require.NotNil(t, lim)
		require.NotNil(t, rt, "enabled config resolves a runtime bundle")

		for range 2 { // drain the 2-token bucket
			d, err := lim.Admit(ctx, key)
			require.NoError(t, err)
			require.True(t, d.Allowed)
			require.NoError(t, lim.Charge(ctx, key, 1))
		}
		d, err := lim.Admit(ctx, key)
		require.NoError(t, err)
		assert.False(t, d.Allowed, "drained bucket rejects")

		if c, ok := lim.(interface{ Close() error }); ok {
			require.NoError(t, c.Close())
		}
	})

	t.Run("bad trusted proxy cidr fails closed", func(t *testing.T) {
		t.Parallel()
		_, _, err := buildRateLimiter(&config.RateLimitConfig{
			Enabled:        true,
			Backend:        "memory",
			IP:             config.RateLimitProfile{Capacity: 60, RefillPerSec: 1},
			Principal:      config.RateLimitProfile{Capacity: 120, RefillPerSec: 2},
			TrustedProxies: []string{"not-a-cidr"},
		})
		assert.Error(t, err, "runtime must not assume config vet ran")
	})
}
