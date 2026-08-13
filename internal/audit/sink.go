package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sync"

	"github.com/darmiel/talmi/internal/core"
)

// Sink is an export destination for audit events.
// Emit must be safe for concurrent use and should not block.
type Sink interface {
	Emit(ctx context.Context, event core.Event) error
	Close() error
}

var _ Sink = (*StdoutSink)(nil)

// StdoutSink writes one JSON object per line to the provided io.Writer (stdout by default).
type StdoutSink struct {
	mu sync.Mutex
	w  io.Writer
}

func NewStdoutSink(w io.Writer) *StdoutSink {
	return &StdoutSink{
		w: w,
	}
}

func (s *StdoutSink) Emit(ctx context.Context, event core.Event) error {
	b, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("marshalling audit event: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.w.Write(append(b, '\n')); err != nil {
		return fmt.Errorf("writing audit event: %w", err)
	}
	return nil
}

func (s *StdoutSink) Close() error {
	return nil // nothing to close :)
}
