package audit

import (
	"context"

	"github.com/darmiel/talmi/internal/core"
)

var _ core.Auditor = (*NoopAuditor)(nil)

// NoopAuditor is an auditor that does nothing.
type NoopAuditor struct{}

func NewNoopAuditor() *NoopAuditor {
	return &NoopAuditor{}
}

func (n *NoopAuditor) Log(ctx context.Context, entry core.AuditEntry) error {
	return nil
}

func (n *NoopAuditor) Query(ctx context.Context, filter core.AuditFilter) ([]core.AuditEntry, error) {
	return nil, nil
}

func (n *NoopAuditor) Close() error {
	return nil
}
