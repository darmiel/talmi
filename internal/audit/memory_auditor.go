package audit

import (
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

func (i *InMemoryAuditor) Find(filter func(entry core.AuditEntry) bool, limit int) ([]core.AuditEntry, error) {
	i.mu.Lock()
	defer i.mu.Unlock()

	var matches []core.AuditEntry
	for _, entry := range i.entries {
		if filter(entry) {
			matches = append(matches, entry)
		}
	}

	if len(matches) > limit {
		matches = matches[len(matches)-limit:]
	}

	return matches, nil
}

func (i *InMemoryAuditor) Close() error {
	return nil // nothing to close :)
}
