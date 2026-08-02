package tasks

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/darmiel/talmi/internal/logging"
)

func TestTriggerRunsAndWaitDrains(t *testing.T) {
	t.Parallel()
	m := NewManager(context.Background())
	var runs atomic.Int32
	m.Register("t", 0, func(context.Context, logging.InternalLogger) error {
		runs.Add(1)
		return nil
	})
	require.NoError(t, m.Trigger("t"))
	m.Wait()
	assert.Equal(t, int32(1), runs.Load())
}

func TestTriggerNotFound(t *testing.T) {
	t.Parallel()
	m := NewManager(context.Background())
	assert.Error(t, m.Trigger("nope"))
}

func TestSchedulerStopsOnCancel(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	m := NewManager(ctx)
	var runs atomic.Int32
	m.Register("t", 5*time.Millisecond, func(context.Context, logging.InternalLogger) error {
		runs.Add(1)
		return nil
	})

	assert.Eventually(t, func() bool { return runs.Load() > 0 }, time.Second, time.Millisecond)

	cancel()
	m.Wait() // returns once the scheduler sees ctx.Done and any in-flight run finishes

	after := runs.Load()
	time.Sleep(30 * time.Millisecond)
	assert.Equal(t, after, runs.Load(), "no further runs after cancel + wait")
}
