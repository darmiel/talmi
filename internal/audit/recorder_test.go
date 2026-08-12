package audit

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/darmiel/talmi/internal/core"
	"github.com/darmiel/talmi/internal/correlation"
)

// capturingAuditor records the events passed to Log. The embedded core.Auditor
// satisfies the interface; only Log is exercised here.
type capturingAuditor struct {
	core.Auditor
	logged []core.Event
}

func (c *capturingAuditor) Log(_ context.Context, e core.Event) error {
	c.logged = append(c.logged, e)
	return nil
}

func TestRecorderFillsFromContext(t *testing.T) {
	t.Parallel()
	is := assert.New(t)
	must := require.New(t)

	cap := &capturingAuditor{}
	r := NewRecorder(cap)

	ctx := correlation.WithSession(correlation.With(context.Background(), "req1"), "sess1")
	err := r.Record(ctx, core.ActionSessionLogin, core.OutcomeSuccess,
		WithActor(&core.Principal{ID: "alice"}))
	must.NoError(err)

	must.Len(cap.logged, 1)
	e := cap.logged[0]
	is.Equal(core.ActionSessionLogin, e.Action)
	is.Equal(core.OutcomeSuccess, e.Outcome)
	is.Equal("req1", e.RequestID)
	is.Equal("sess1", e.SessionID)
	must.NotNil(e.Actor)
	is.Equal("alice", e.Actor.ID)
	is.NotEmpty(e.ID)
	is.False(e.Time.IsZero())
}

func TestRecorderOptions(t *testing.T) {
	t.Parallel()

	t.Run("with error sets the message", func(t *testing.T) {
		t.Parallel()
		is := assert.New(t)
		must := require.New(t)

		cap := &capturingAuditor{}
		r := NewRecorder(cap)

		must.NoError(r.Record(context.Background(), core.ActionLeaseIssue, core.OutcomeFailure,
			WithError(errors.New("boom"))))
		must.Len(cap.logged, 1)
		is.Equal("boom", cap.logged[0].Error)
	})

	t.Run("with nil error leaves it empty", func(t *testing.T) {
		t.Parallel()
		is := assert.New(t)
		must := require.New(t)

		cap := &capturingAuditor{}
		r := NewRecorder(cap)

		must.NoError(r.Record(context.Background(), core.ActionLeaseIssue, core.OutcomeSuccess,
			WithError(nil)))
		must.Len(cap.logged, 1)
		is.Empty(cap.logged[0].Error)
	})

	t.Run("with metadata revision and artifacts", func(t *testing.T) {
		t.Parallel()
		is := assert.New(t)
		must := require.New(t)

		cap := &capturingAuditor{}
		r := NewRecorder(cap)

		must.NoError(r.Record(context.Background(), core.ActionTaskTrigger, core.OutcomeSuccess,
			WithRevision("rev9"),
			WithMetadata(map[string]any{"task": "reload"}),
			WithArtifacts([]core.ArtifactAudit{{ArtifactID: "a1"}}),
		))
		must.Len(cap.logged, 1)
		e := cap.logged[0]
		is.Equal("rev9", e.Revision)
		is.Equal("reload", e.Metadata["task"])
		must.Len(e.Artifacts, 1)
		is.Equal("a1", e.Artifacts[0].ArtifactID)
	})
}
