package audit

import (
	"context"
	"time"

	"github.com/rs/xid"

	"github.com/darmiel/talmi/internal/core"
	"github.com/darmiel/talmi/internal/correlation"
)

type Recorder struct {
	auditor core.Auditor
}

func NewRecorder(auditor core.Auditor) *Recorder {
	return &Recorder{auditor: auditor}
}

// Option mutates an audit event before it is recorded.
type Option func(*core.Event)

func WithActor(actor *core.Principal) Option {
	return func(e *core.Event) { e.Actor = actor }
}

func WithError(err error) Option {
	return func(e *core.Event) {
		if err != nil {
			e.Error = err.Error()
		}
	}
}

// WithRevision records the config revision in effect.
func WithRevision(rev string) Option {
	return func(e *core.Event) { e.Revision = rev }
}

// WithMetadata attaches event-specific extras.
func WithMetadata(m map[string]any) Option {
	return func(e *core.Event) { e.Metadata = m }
}

// WithDecision attaches the authorization decision trace (lease events).
func WithDecision(d *core.Decision) Option {
	return func(e *core.Event) { e.Decision = d }
}

// WithArtifacts attaches the issued artifacts (lease events).
func WithArtifacts(a []core.ArtifactAudit) Option {
	return func(e *core.Event) { e.Artifacts = a }
}

func (r *Recorder) Record(ctx context.Context, action core.AuditAction, outcome core.Outcome, opts ...Option) error {
	e := core.Event{
		ID:        xid.New().String(),
		Time:      time.Now(),
		Action:    action,
		Outcome:   outcome,
		RequestID: correlation.From(ctx),
		SessionID: correlation.SessionFrom(ctx),
	}
	for _, opt := range opts {
		opt(&e)
	}
	return r.auditor.Log(context.WithoutCancel(ctx), e)
}
