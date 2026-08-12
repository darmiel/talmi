package audit

import (
	"context"
	"sync"
	"time"

	"github.com/darmiel/talmi/internal/core"
)

var _ core.Auditor = (*InMemoryAuditor)(nil)

// InMemoryAuditor is an auditor that stores audit logs in memory.
type InMemoryAuditor struct {
	mu     sync.Mutex
	events []core.Event
}

func NewInMemoryAuditor() *InMemoryAuditor {
	return &InMemoryAuditor{
		events: make([]core.Event, 0),
	}
}

func (i *InMemoryAuditor) Log(_ context.Context, event core.Event) error {
	i.mu.Lock()
	defer i.mu.Unlock()

	i.events = append(i.events, event)
	return nil
}

func (i *InMemoryAuditor) Query(_ context.Context, f core.AuditFilter) (matches []core.Event, _ error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	for _, e := range i.events {
		if matchFilter(e, f) {
			matches = append(matches, e)
		}
	}
	return limitTail(matches, f.Limit), nil
}

func (i *InMemoryAuditor) Prune(_ context.Context, before time.Time) (int, error) {
	i.mu.Lock()
	defer i.mu.Unlock()

	kept := i.events[:0:0]
	removed := 0
	for _, e := range i.events {
		if e.Time.Before(before) {
			removed++
			continue
		}
		kept = append(kept, e)
	}
	i.events = kept
	return removed, nil
}

func (i *InMemoryAuditor) Close() error {
	return nil // nothing to close :)
}
