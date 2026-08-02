package audit

import (
	"context"
	"sync"

	"github.com/darmiel/talmi/internal/core"
)

var _ core.Auditor = (*InMemoryAuditor)(nil)

// InMemoryAuditor is an auditor that stores audit logs in memory.
type InMemoryAuditor struct {
	mu      sync.Mutex
	entries []core.AuditEntry
}

func NewInMemoryAuditor() *InMemoryAuditor {
	return &InMemoryAuditor{
		entries: make([]core.AuditEntry, 0),
	}
}

func (i *InMemoryAuditor) Log(_ context.Context, entry core.AuditEntry) error {
	i.mu.Lock()
	defer i.mu.Unlock()

	i.entries = append(i.entries, entry)
	return nil
}

func (i *InMemoryAuditor) Query(_ context.Context, f core.AuditFilter) (matches []core.AuditEntry, _ error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	for _, e := range i.entries {
		if matchFilter(e, f) {
			matches = append(matches, e)
		}
	}
	return limitTail(matches, f.Limit), nil
}

func (i *InMemoryAuditor) Close() error {
	return nil // nothing to close :)
}
