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

	capt := &capturingAuditor{}
	r := NewRecorder(capt)

	ctx := correlation.WithSession(correlation.With(context.Background(), "req1"), "sess1")
	err := r.Record(ctx, core.ActionSessionLogin, core.OutcomeSuccess,
		WithActor(&core.Principal{ID: "alice"}))
	must.NoError(err)

	must.Len(capt.logged, 1)
	e := capt.logged[0]
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

		capt := &capturingAuditor{}
		r := NewRecorder(capt)

		must.NoError(r.Record(context.Background(), core.ActionLeaseIssue, core.OutcomeFailure,
			WithError(errors.New("boom"))))
		must.Len(capt.logged, 1)
		is.Equal("boom", capt.logged[0].Error)
	})

	t.Run("with nil error leaves it empty", func(t *testing.T) {
		t.Parallel()
		is := assert.New(t)
		must := require.New(t)

		capt := &capturingAuditor{}
		r := NewRecorder(capt)

		must.NoError(r.Record(context.Background(), core.ActionLeaseIssue, core.OutcomeSuccess,
			WithError(nil)))
		must.Len(capt.logged, 1)
		is.Empty(capt.logged[0].Error)
	})

	t.Run("with metadata revision and artifacts", func(t *testing.T) {
		t.Parallel()
		is := assert.New(t)
		must := require.New(t)

		capt := &capturingAuditor{}
		r := NewRecorder(capt)

		must.NoError(r.Record(context.Background(), core.ActionTaskTrigger, core.OutcomeSuccess,
			WithRevision("rev9"),
			WithMetadata(map[string]any{"task": "reload"}),
			WithArtifacts([]core.ArtifactAudit{{ArtifactID: "a1"}}),
		))
		must.Len(capt.logged, 1)
		e := capt.logged[0]
		is.Equal("rev9", e.Revision)
		is.Equal("reload", e.Metadata["task"])
		must.Len(e.Artifacts, 1)
		is.Equal("a1", e.Artifacts[0].ArtifactID)
	})
}

type captureSink struct {
	events []core.Event
	err    error
}

func (c *captureSink) Emit(_ context.Context, e core.Event) error {
	c.events = append(c.events, e)
	return c.err
}
func (c *captureSink) Close() error { return nil }

func TestRecorderFansOutToSinks(t *testing.T) {
	t.Parallel()
	is := assert.New(t)
	must := require.New(t)

	auditor := &capturingAuditor{}
	sink := &captureSink{}
	r := NewRecorder(auditor, sink)

	must.NoError(r.Record(context.Background(), core.ActionLeaseIssue, core.OutcomeSuccess))
	must.Len(auditor.logged, 1)
	must.Len(sink.events, 1)
	is.Equal(auditor.logged[0].ID, sink.events[0].ID)
}

func TestRecorderSinkFailureIsIsolated(t *testing.T) {
	t.Parallel()
	must := require.New(t)

	auditor := &capturingAuditor{}
	sink := &captureSink{err: errors.New("sink down")}
	r := NewRecorder(auditor, sink)

	must.NoError(r.Record(context.Background(), core.ActionLeaseIssue, core.OutcomeSuccess),
		"a failing sink must not fail the record call")
	must.Len(auditor.logged, 1, "the store write still happened")
}
