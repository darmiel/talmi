//go:build integration

package postgres

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/darmiel/talmi/internal/core"
)

func newTestAuditor(t *testing.T) *Auditor {
	t.Helper()
	dsn := os.Getenv("TALMI_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TALMI_TEST_DATABASE_URL to run postgres integration tests (schema must be migrated)")
	}
	pool, err := Connect(context.Background(), dsn, 10*time.Second)
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	_, err = pool.Exec(context.Background(), `TRUNCATE audit_log CASCADE`)
	require.NoError(t, err)
	return &Auditor{pool: pool}
}

func sampleEvent(id string, ts time.Time, action core.AuditAction, outcome core.Outcome) core.Event {
	return core.Event{
		ID:        id,
		Time:      ts,
		Action:    action,
		Outcome:   outcome,
		Actor:     &core.Principal{ID: "pipeline/deploy", Issuer: "concourse"},
		RequestID: "req-" + id,
		SessionID: "sess-" + id,
		Revision:  "abc123",
	}
}

func TestPostgresAuditRoundTrip(t *testing.T) {
	is := assert.New(t)
	must := require.New(t)

	a := newTestAuditor(t)
	ctx := context.Background()

	base := time.Now().UTC().Truncate(time.Second)
	issue := sampleEvent("e1", base, core.ActionLeaseIssue, core.OutcomeSuccess)
	issue.Artifacts = []core.ArtifactAudit{
		{ArtifactID: "art1", Provider: "github", Fingerprint: "fp1"},
		{ArtifactID: "art2", Provider: "github", Fingerprint: "fp2"},
	}
	login := sampleEvent("e2", base.Add(time.Second), core.ActionSessionLogin, core.OutcomeFailure)

	must.NoError(a.Log(ctx, issue))
	must.NoError(a.Log(ctx, login))

	t.Run("no filter returns newest first", func(t *testing.T) {
		got, err := a.Query(ctx, core.AuditFilter{})
		must.NoError(err)
		must.Len(got, 2)
		is.Equal("e2", got[0].ID) // ORDER BY time DESC
		is.Equal("e1", got[1].ID)
	})

	t.Run("artifacts round-trip", func(t *testing.T) {
		got, err := a.Query(ctx, core.AuditFilter{ID: "e1"})
		must.NoError(err)
		must.Len(got, 1)
		must.Len(got[0].Artifacts, 2)
		is.Equal("art1", got[0].Artifacts[0].ArtifactID)
		is.Equal("concourse", got[0].Actor.Issuer)
	})

	t.Run("filter by action", func(t *testing.T) {
		got, err := a.Query(ctx, core.AuditFilter{Action: core.ActionSessionLogin})
		must.NoError(err)
		must.Len(got, 1)
		is.Equal("e2", got[0].ID)
	})

	t.Run("filter by outcome", func(t *testing.T) {
		got, err := a.Query(ctx, core.AuditFilter{Outcome: core.OutcomeFailure})
		must.NoError(err)
		must.Len(got, 1)
		is.Equal("e2", got[0].ID)
	})

	t.Run("filter by request id", func(t *testing.T) {
		got, err := a.Query(ctx, core.AuditFilter{RequestID: "req-e1"})
		must.NoError(err)
		must.Len(got, 1)
		is.Equal("e1", got[0].ID)
	})

	t.Run("filter by session id", func(t *testing.T) {
		got, err := a.Query(ctx, core.AuditFilter{SessionID: "sess-e2"})
		must.NoError(err)
		must.Len(got, 1)
		is.Equal("e2", got[0].ID)
	})

	t.Run("filter by actor id", func(t *testing.T) {
		got, err := a.Query(ctx, core.AuditFilter{ActorID: "pipeline/deploy"})
		must.NoError(err)
		is.Len(got, 2)
	})

	t.Run("filter by fingerprint", func(t *testing.T) {
		got, err := a.Query(ctx, core.AuditFilter{Fingerprint: "fp2"})
		must.NoError(err)
		must.Len(got, 1)
		is.Equal("e1", got[0].ID)
	})

	t.Run("limit", func(t *testing.T) {
		got, err := a.Query(ctx, core.AuditFilter{Limit: 1})
		must.NoError(err)
		must.Len(got, 1)
		is.Equal("e2", got[0].ID) // newest
	})
}

func TestPostgresAuditPruneCascades(t *testing.T) {
	is := assert.New(t)
	must := require.New(t)

	a := newTestAuditor(t)
	ctx := context.Background()

	base := time.Now().UTC().Truncate(time.Second)
	old := sampleEvent("old", base.Add(-2*time.Hour), core.ActionLeaseIssue, core.OutcomeSuccess)
	old.Artifacts = []core.ArtifactAudit{{ArtifactID: "old-art", Provider: "github", Fingerprint: "fp-old"}}
	fresh := sampleEvent("fresh", base, core.ActionLeaseIssue, core.OutcomeSuccess)

	must.NoError(a.Log(ctx, old))
	must.NoError(a.Log(ctx, fresh))

	removed, err := a.Prune(ctx, base.Add(-time.Hour))
	must.NoError(err)
	is.Equal(1, removed)

	got, err := a.Query(ctx, core.AuditFilter{})
	must.NoError(err)
	must.Len(got, 1)
	is.Equal("fresh", got[0].ID)

	// the old event's artifact must be gone via ON DELETE CASCADE
	var count int
	must.NoError(a.pool.QueryRow(ctx,
		`SELECT count(*) FROM audit_artifacts WHERE entry_id = $1`, "old").Scan(&count))
	is.Zero(count)
}
