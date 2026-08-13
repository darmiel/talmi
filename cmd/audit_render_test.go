package cmd

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/darmiel/talmi/internal/cli/ui"
	"github.com/darmiel/talmi/internal/core"
)

func TestRenderAuditCardSuccess(t *testing.T) {
	t.Parallel()
	is := assert.New(t)
	must := require.New(t)

	var buf bytes.Buffer
	p := ui.New(&buf, false)
	now := time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)
	e := core.Event{
		ID: "ce4fbra0mn28", Action: core.ActionLeaseIssue, Outcome: core.OutcomeSuccess,
		Time: now.Add(-2 * time.Minute), Actor: &core.Principal{ID: "svc-pipeline"},
		Artifacts: []core.ArtifactAudit{{ArtifactID: "a1"}},
	}
	renderAuditCard(p, now, e)

	out := buf.String()
	is.Contains(out, "lease.issue")
	is.Contains(out, "2m ago")
	is.Contains(out, "svc-pipeline")
	is.Contains(out, "ce4fbra0mn28", "full id is copy-pasteable")
	is.Contains(out, "1 artifact")
	// headline + context line (+ trailing blank separator)
	must.GreaterOrEqual(strings.Count(out, "\n"), 2, "success card is a compact multi-line block")
}

func TestRenderAuditCardFailureExpands(t *testing.T) {
	t.Parallel()
	is := assert.New(t)

	var buf bytes.Buffer
	p := ui.New(&buf, false)
	now := time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)
	e := core.Event{
		ID: "e2", Action: core.ActionLeaseIssue, Outcome: core.OutcomeFailure,
		Time: now.Add(-4 * time.Minute), Actor: &core.Principal{ID: "svc", Issuer: "concourse"},
		RequestID: "req9", Revision: "abc123", Error: "persisting lease failed: db down",
	}
	renderAuditCard(p, now, e)

	out := buf.String()
	is.Contains(out, "failed")
	is.Contains(out, "svc (concourse)")
	is.Contains(out, "persisting lease failed: db down")
	is.Contains(out, "req9")
	is.Contains(out, "e2")
	is.Greater(strings.Count(strings.TrimRight(out, "\n"), "\n"), 0, "failure card is multi-line")
}

func TestRenderAuditSummaryCounts(t *testing.T) {
	t.Parallel()
	is := assert.New(t)

	var buf bytes.Buffer
	p := ui.New(&buf, false)
	entries := []core.Event{
		{Outcome: core.OutcomeSuccess},
		{Outcome: core.OutcomeSuccess},
		{Outcome: core.OutcomeDenied},
		{Outcome: core.OutcomeFailure},
	}
	renderAuditSummary(p, entries, "action=lease.issue")
	out := buf.String()
	is.Contains(out, "4 entries")
	is.Contains(out, "2 ok")
	is.Contains(out, "1 denied")
	is.Contains(out, "1 failed")
	is.Contains(out, "action=lease.issue")
}

func TestRenderAuditDetailSections(t *testing.T) {
	t.Parallel()
	is := assert.New(t)

	d, out, _ := testDeps(&fakeClient{})
	e := core.Event{
		ID: "e1", Action: core.ActionLeaseIssue, Outcome: core.OutcomeSuccess,
		Time: time.Now(), RequestID: "req1", Revision: "abc123",
		Actor: &core.Principal{
			ID:         "svc",
			Issuer:     "concourse",
			Attributes: map[string]any{"teams": []any{"acme/admins"}},
		},
		Metadata:  map[string]any{"lease_id": "e1"},
		Artifacts: []core.ArtifactAudit{{ArtifactID: "art1", Provider: "gh-deploy", Fingerprint: "fp1"}},
		Decision:  &core.Decision{Authorized: true, PolicyNames: []string{"read"}},
	}
	renderAuditDetail(d, e)

	s := out.String()
	is.Contains(s, "Trace")
	is.Contains(s, "Actor")
	is.Contains(s, "concourse")
	is.Contains(s, "acme/admins")
	is.Contains(s, "Metadata")
	is.Contains(s, "Artifacts")
	is.Contains(s, "fp1")
	is.Contains(s, "Decision")
	is.Contains(s, "authorized")
}

func TestRenderAuditDetailErrorSection(t *testing.T) {
	t.Parallel()
	is := assert.New(t)
	d, out, _ := testDeps(&fakeClient{})
	renderAuditDetail(d, core.Event{
		ID: "e3", Action: core.ActionSessionLogin, Outcome: core.OutcomeFailure, Error: "bad token",
	})
	s := out.String()
	is.Contains(s, "Error")
	is.Contains(s, "bad token")
}
