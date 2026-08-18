package ratelimit

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

func TestMemoryBackendConcurrent(t *testing.T) {
	t.Parallel()
	m := NewMemoryLimiter(MemoryOptions{Sweep: 0}) // no sweeper here
	defer func(m *MemoryLimiter) {
		err := m.Close()
		if err != nil {
			t.Errorf("failed to close memory limiter: %v", err)
		}
	}(m)
	key := Key{Layer: "ip", ID: "1.2.3.4", Profile: Profile{Capacity: 100, RefillPerSec: 0}}
	var wg sync.WaitGroup
	for range 500 {
		wg.Go(func() {
			if d, _ := m.Admit(context.Background(), key); d.Allowed {
				_ = m.Charge(context.Background(), key, 1)
			}
		})
	}
	wg.Wait()
	// at most `capacity` admits could have charged; balance never below -capacity
	d, _ := m.Admit(context.Background(), key)
	assert.False(t, d.Allowed)
}

func TestMemoryBackendLazyRefill(t *testing.T) {
	t.Parallel()
	must := require.New(t)
	clk := &fakeClock{t: time.Unix(0, 0)}
	m := NewMemoryLimiter(MemoryOptions{Now: clk.now})
	defer func(m *MemoryLimiter) {
		err := m.Close()
		if err != nil {
			t.Errorf("failed to close memory limiter: %v", err)
		}
	}(m)
	key := Key{Layer: "ip", ID: "x", Profile: Profile{Capacity: 5, RefillPerSec: 1}}

	for range 5 {
		d, err := m.Admit(context.Background(), key)
		must.NoError(err)
		must.True(d.Allowed)
		must.NoError(m.Charge(context.Background(), key, 1))
	}
	d, err := m.Admit(context.Background(), key)
	must.NoError(err)
	must.False(d.Allowed, "drained bucket rejects")

	clk.t = clk.t.Add(2 * time.Second) // refill 2 tokens
	d, err = m.Admit(context.Background(), key)
	must.NoError(err)
	must.True(d.Allowed, "refills after time passes")
}

func TestMemoryBackendEvictsIdle(t *testing.T) {
	t.Parallel()
	must := require.New(t)
	clk := &fakeClock{t: time.Unix(0, 0)}
	m := NewMemoryLimiter(MemoryOptions{Now: clk.now, IdleTTL: 30 * time.Second}) // Sweep 0: sweep manually
	defer func(m *MemoryLimiter) {
		err := m.Close()
		if err != nil {
			t.Errorf("failed to close memory limiter: %v", err)
		}
	}(m)
	key := Key{Layer: "ip", ID: "gone", Profile: Profile{Capacity: 5, RefillPerSec: 1}}

	_, err := m.Admit(context.Background(), key)
	must.NoError(err)
	must.Equal(1, m.count(), "bucket created on first touch")

	clk.t = clk.t.Add(time.Minute) // idle beyond TTL
	m.sweep()
	must.Equal(0, m.count(), "idle bucket evicted")
}

func TestMemorySweeperStartsAndStops(t *testing.T) {
	t.Parallel()
	m := NewMemoryLimiter(MemoryOptions{Sweep: 10 * time.Millisecond, IdleTTL: time.Second})
	time.Sleep(30 * time.Millisecond) // let the sweeper tick at least once
	require.NoError(t, m.Close())
	// goleak (TestMain) fails if the sweeper goroutine outlives Close.
}
