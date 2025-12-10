package audit

import (
	"sync"

	"github.com/darmiel/talmi/internal/core"
)

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

func (i *InMemoryAuditor) Log(entry core.AuditEntry) error {
	i.mu.Lock()
	defer i.mu.Unlock()

	i.entries = append(i.entries, entry)
	return nil
}

func (i *InMemoryAuditor) GetRecent(limit int) ([]core.AuditEntry, error) {
	i.mu.Lock()
	defer i.mu.Unlock()

	if limit > len(i.entries) {
		limit = len(i.entries)
	}
	start := len(i.entries) - limit
	entries := make([]core.AuditEntry, limit)
	copy(entries, i.entries[start:])

	return entries, nil
}

func (i *InMemoryAuditor) Close() error {
	return nil // nothing to close :)
}
