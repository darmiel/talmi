package audit

import "github.com/darmiel/talmi/internal/core"

var _ core.Auditor = (*NoopAuditor)(nil)

// NoopAuditor is an auditor that does nothing.
type NoopAuditor struct{}

func NewNoopAuditor() *NoopAuditor {
	return &NoopAuditor{}
}

func (n *NoopAuditor) Log(_ core.AuditEntry) error {
	return nil
}

func (n *NoopAuditor) GetRecent(_ int) ([]core.AuditEntry, error) {
	return []core.AuditEntry{}, nil
}

func (n *NoopAuditor) Find(_ func(entry core.AuditEntry) bool, _ int) ([]core.AuditEntry, error) {
	return []core.AuditEntry{}, nil
}

func (n *NoopAuditor) Close() error {
	return nil
}
