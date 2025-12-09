package audit

import "github.com/darmiel/talmi/internal/core"

// NoopAuditor is an auditor that does nothing.
type NoopAuditor struct{}

func NewNoopAuditor() *NoopAuditor {
	return &NoopAuditor{}
}

func (n *NoopAuditor) Log(entry core.AuditEntry) error {
	return nil
}

func (n *NoopAuditor) GetRecent(limit int) ([]core.AuditEntry, error) {
	return []core.AuditEntry{}, nil
}

func (n *NoopAuditor) Close() error {
	return nil
}
