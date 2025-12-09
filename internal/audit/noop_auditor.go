package audit

import "github.com/darmiel/talmi/internal/core"

// NoopAuditor is an auditor that does nothing.
type NoopAuditor struct{}

func NewNoopAuditor() *NoopAuditor {
	return &NoopAuditor{}
}

func (n *NoopAuditor) Log(entry core.AuditEntry) error {
	// noop
	return nil
}

func (n *NoopAuditor) Close() error {
	// nothing to close
	return nil
}
