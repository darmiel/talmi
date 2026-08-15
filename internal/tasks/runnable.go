package tasks

import (
	"context"
	"fmt"
	"runtime/debug"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

type RunnableTask struct {
	Name     string
	Interval time.Duration
	Handler  TaskFunc
	Timeout  time.Duration

	registeredAt time.Time

	mu         sync.RWMutex
	Running    bool
	LastRun    time.Time
	LastResult string
	Logs       []LogEntry
}

func (t *RunnableTask) Run(parent context.Context) {
	t.mu.Lock()

	l := log.With().Str("task", t.Name).Logger()
	if t.Running {
		t.mu.Unlock()
		l.Warn().Msg("task is already running, skipping execution")
		return
	}
	t.Running = true
	t.Logs = make([]LogEntry, 0)
	t.mu.Unlock()

	defer func() {
		t.mu.Lock()
		t.Running = false
		t.LastRun = time.Now()
		t.mu.Unlock()
	}()

	taskLogger := NewCompositeLogger(t, l)
	taskLogger.Info("starting task execution")

	timeout := t.Timeout
	if timeout <= 0 {
		timeout = DefaultTaskTimeout
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()

	defer func() {
		if r := recover(); r != nil {
			t.mu.Lock()
			t.LastResult = fmt.Sprintf("panicked: %v", r)
			t.mu.Unlock()
			l.Error().Interface("panic", r).Bytes("stack", debug.Stack()).Msg("task panicked")
		}
	}()

	start := time.Now()
	err := t.Handler(ctx, taskLogger)
	duration := time.Since(start)

	t.mu.Lock()
	if err != nil {
		t.LastResult = fmt.Sprintf("failed: %v", err)
	} else {
		t.LastResult = "success"
	}
	t.mu.Unlock()

	if err != nil {
		taskLogger.Error("task failed after %s: %v", duration, err)
	} else {
		taskLogger.Info("task completed successfully in %s", duration)
	}
}

func (t *RunnableTask) Status() TaskStatus {
	t.mu.RLock()
	defer t.mu.RUnlock()

	var nextTime time.Time
	if t.Interval > 0 {
		if !t.LastRun.IsZero() {
			nextTime = t.LastRun.Add(t.Interval)
		} else {
			nextTime = t.registeredAt.Add(t.Interval)
		}
	}

	s := TaskStatus{
		Name:       t.Name,
		Running:    t.Running,
		LastRun:    t.LastRun,
		LastResult: t.LastResult,
		NextRun:    nextTime,
	}
	return s
}

func (t *RunnableTask) GetLogs() []LogEntry {
	t.mu.RLock()
	defer t.mu.RUnlock()

	cpy := make([]LogEntry, len(t.Logs))
	copy(cpy, t.Logs)
	return cpy
}

func (t *RunnableTask) AppendLog(level, msg string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.Logs = append(t.Logs, LogEntry{
		Time:    time.Now(),
		Level:   level,
		Message: msg,
	})

	if len(t.Logs) > MaxLogsPerTask {
		t.Logs = t.Logs[1:]
	}
}
