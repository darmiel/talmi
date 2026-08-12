package audit

import (
	"context"
	"time"

	"github.com/darmiel/talmi/internal/core"
)

var _ core.Auditor = (*NoopAuditor)(nil)

// NoopAuditor is an auditor that does nothing.
type NoopAuditor struct{}

func NewNoopAuditor() *NoopAuditor {
	return &NoopAuditor{}
}

func (n *NoopAuditor) Log(_ context.Context, _ core.Event) error {
	return nil
}

func (n *NoopAuditor) Query(_ context.Context, _ core.AuditFilter) ([]core.Event, error) {
	return nil, nil
}

func (n *NoopAuditor) Prune(_ context.Context, _ time.Time) (int, error) {
	return 0, nil
}

func (n *NoopAuditor) Close() error {
	return nil
}
