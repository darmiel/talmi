package tasks

import (
	"context"
	"time"

	"github.com/darmiel/talmi/internal/logging"
)

// TaskFunc is the unit of work.
// It receives a TaskLogger which stores the logging output (at runtime).
type TaskFunc func(ctx context.Context, logger logging.InternalLogger) error

type TaskDefinition struct {
	Name     string
	Interval time.Duration
	Handler  TaskFunc
}

type TaskStatus struct {
	Name       string    `json:"name,omitempty"`
	Running    bool      `json:"running,omitempty"`
	LastRun    time.Time `json:"last_run"`
	LastResult string    `json:"last_result,omitempty"`
	NextRun    time.Time `json:"next_run"`
}

type LogEntry struct {
	Time    time.Time `json:"time"`
	Level   string    `json:"level,omitempty"`
	Message string    `json:"message,omitempty"`
}
