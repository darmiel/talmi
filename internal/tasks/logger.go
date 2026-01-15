package tasks

import (
	"fmt"

	"github.com/rs/zerolog"

	"github.com/darmiel/talmi/internal/logging"
)

var _ logging.InternalLogger = (*TaskStoreLogger)(nil)

type TaskStoreLogger struct {
	Task *RunnableTask
}

func NewTaskStoreLogger(task *RunnableTask) *TaskStoreLogger {
	return &TaskStoreLogger{
		Task: task,
	}
}

func (t *TaskStoreLogger) Debug(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	t.Task.AppendLog("debug", msg)
}

func (t *TaskStoreLogger) Info(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	t.Task.AppendLog("info", msg)
}

func (t *TaskStoreLogger) Warn(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	t.Task.AppendLog("warn", msg)
}

func (t *TaskStoreLogger) Error(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	t.Task.AppendLog("error", msg)
}

// NewCompositeLogger creates a MultiLogger that logs to both zerolog and the task store.
func NewCompositeLogger(task *RunnableTask, zlog zerolog.Logger) logging.MultiLogger {
	return logging.NewMultiLogger(
		// first log the task using zerlog,
		logging.NewZLogger(zlog),
		// then store it in the task logs
		NewTaskStoreLogger(task),
	)
}
