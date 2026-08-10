package tasks

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/darmiel/talmi/internal/logging"
)

func TestTaskPanicIsRecovered(t *testing.T) {
	t.Parallel()

	task := &RunnableTask{
		Name: "boom",
		Handler: func(context.Context, logging.InternalLogger) error {
			panic("kaboom")
		},
	}

	require.NotPanics(t, func() {
		task.Run(context.Background())
	}, "a panicking task handler must be recovered, not crash the process")

	task.mu.RLock()
	last := task.LastResult
	task.mu.RUnlock()
	assert.True(t, strings.Contains(strings.ToLower(last), "panic"),
		"the recovered panic must be recorded in LastResult, got %q", last)
}
