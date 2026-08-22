package audit

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/darmiel/talmi/internal/core"
)

func TestInMemoryAuditorQuery(t *testing.T) {
	t.Parallel()

	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	events := []core.Event{
		{
			ID:        "e1",
			Time:      base,
			Action:    core.ActionLeaseIssue,
			Outcome:   core.OutcomeSuccess,
			RequestID: "req1",
			SessionID: "sess1",
			NodeID:    "node-a",
			Actor:     &core.Principal{ID: "alice"},
			Artifacts: []core.ArtifactAudit{{ArtifactID: "a1", Fingerprint: "fp1"}},
		},
		{
			ID:        "e2",
			Time:      base.Add(time.Hour),
			Action:    core.ActionSessionLogin,
			Outcome:   core.OutcomeFailure,
			RequestID: "req2",
			SessionID: "sess2",
			NodeID:    "node-b",
			Actor:     &core.Principal{ID: "bob"},
		},
		{
			ID:        "e3",
			Time:      base.Add(2 * time.Hour),
			Action:    core.ActionLeaseIssue,
			Outcome:   core.OutcomeDenied,
			RequestID: "req1",
			NodeID:    "node-a",
			Actor:     &core.Principal{ID: "alice"},
		},
	}

	tests := []struct {
		name    string
		filter  core.AuditFilter
		wantIDs []string
	}{
		{"no filter returns all", core.AuditFilter{}, []string{"e1", "e2", "e3"}},
		{"by action", core.AuditFilter{Action: core.ActionLeaseIssue}, []string{"e1", "e3"}},
		{"by outcome", core.AuditFilter{Outcome: core.OutcomeDenied}, []string{"e3"}},
		{"by request id", core.AuditFilter{RequestID: "req1"}, []string{"e1", "e3"}},
		{"by session id", core.AuditFilter{SessionID: "sess2"}, []string{"e2"}},
		{"by actor id", core.AuditFilter{ActorID: "bob"}, []string{"e2"}},
		{"by node", core.AuditFilter{NodeID: "node-a"}, []string{"e1", "e3"}},
		{"by id", core.AuditFilter{ID: "e2"}, []string{"e2"}},
		{"by fingerprint", core.AuditFilter{Fingerprint: "fp1"}, []string{"e1"}},
		{"since inclusive lower bound", core.AuditFilter{Since: base.Add(time.Hour)}, []string{"e2", "e3"}},
		{"until inclusive upper bound", core.AuditFilter{Until: base.Add(time.Hour)}, []string{"e1", "e2"}},
		{"limit keeps last n", core.AuditFilter{Limit: 2}, []string{"e2", "e3"}},
		{"no match", core.AuditFilter{Action: core.ActionWebhookReceived}, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			is := assert.New(t)
			must := require.New(t)

			a := NewInMemoryAuditor()
			for _, e := range events {
				must.NoError(a.Log(context.Background(), e))
			}

			got, err := a.Query(context.Background(), tt.filter)
			must.NoError(err)

			var ids []string
			for _, e := range got {
				ids = append(ids, e.ID)
			}
			is.Equal(tt.wantIDs, ids)
		})
	}
}

func TestInMemoryAuditorPrune(t *testing.T) {
	t.Parallel()
	is := assert.New(t)
	must := require.New(t)

	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	a := NewInMemoryAuditor()
	for i, ts := range []time.Time{base, base.Add(time.Hour), base.Add(2 * time.Hour)} {
		must.NoError(a.Log(context.Background(), core.Event{
			ID:   string(rune('a' + i)),
			Time: ts,
		}))
	}

	// cutoff removes only strictly-older rows
	removed, err := a.Prune(context.Background(), base.Add(time.Hour))
	must.NoError(err)
	is.Equal(1, removed)

	got, err := a.Query(context.Background(), core.AuditFilter{})
	must.NoError(err)
	must.Len(got, 2)
	is.Equal("b", got[0].ID)
	is.Equal("c", got[1].ID)
}

func TestNoopAuditor(t *testing.T) {
	t.Parallel()
	is := assert.New(t)
	must := require.New(t)

	a := NewNoopAuditor()
	must.NoError(a.Log(context.Background(), core.Event{ID: "x"}))

	got, err := a.Query(context.Background(), core.AuditFilter{})
	must.NoError(err)
	is.Empty(got)

	removed, err := a.Prune(context.Background(), time.Now())
	must.NoError(err)
	is.Zero(removed)

	must.NoError(a.Close())
}
