package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/darmiel/talmi/internal/core"
	"github.com/darmiel/talmi/internal/logging"
	"github.com/darmiel/talmi/internal/tasks"
)

type fakeAuditor struct {
	entries   []core.Event
	gotFilter core.AuditFilter
	logged    []core.Event
}

func (a *fakeAuditor) Log(_ context.Context, e core.Event) error {
	a.logged = append(a.logged, e)
	return nil
}

func (a *fakeAuditor) Query(_ context.Context, f core.AuditFilter) ([]core.Event, error) {
	a.gotFilter = f
	return a.entries, nil
}
func (a *fakeAuditor) Prune(context.Context, time.Time) (int, error) { return 0, nil }
func (a *fakeAuditor) Close() error                                  { return nil }

func adminHandlerServer(
	t *testing.T,
	principal *core.Principal,
	authorized bool,
	auditor core.Auditor,
	tm *tasks.Manager,
) *Server {
	t.Helper()
	return NewServer(func() TokenService { return nil }, WithAdmin(AdminConfig{
		SessionIssuer: func() (core.Issuer, bool) { return fakeIssuer{principal: principal}, true },
		Authorize: func(*core.Principal, []core.ResourceRequest) core.Decision {
			return core.Decision{Authorized: authorized}
		},
		Auditor:    func() core.Auditor { return auditor },
		Tasks:      tm,
		SessionTTL: time.Hour,
	}))
}

func req(t *testing.T, srv *Server, method, path, auth string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, path, nil)
	if auth != "" {
		r.Header.Set("Authorization", "Bearer "+auth)
	}
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, r)
	return rec
}

func TestAuditQuery(t *testing.T) {
	t.Parallel()
	p := &core.Principal{ID: "alice", Issuer: "gh-human"}
	aud := &fakeAuditor{entries: []core.Event{{ID: "l1", Action: core.ActionLeaseIssue, Outcome: core.OutcomeSuccess}}}

	t.Run("authorized returns entries and parses filter", func(t *testing.T) {
		t.Parallel()
		srv := adminHandlerServer(t, p, true, aud, nil)
		rec := req(t, srv, http.MethodGet, AuditQueryRoute+"?action=lease.issue&limit=10", "session")
		require.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), `"l1"`)
		assert.Equal(t, core.ActionLeaseIssue, aud.gotFilter.Action)
		assert.Equal(t, 10, aud.gotFilter.Limit)
	})

	t.Run("unauthorized -> 403", func(t *testing.T) {
		t.Parallel()
		srv := adminHandlerServer(t, p, false, aud, nil)
		assert.Equal(t, http.StatusForbidden, req(t, srv, http.MethodGet, AuditQueryRoute, "session").Code)
	})

	t.Run("missing session -> 401", func(t *testing.T) {
		t.Parallel()
		srv := adminHandlerServer(t, p, true, aud, nil)
		assert.Equal(t, http.StatusUnauthorized, req(t, srv, http.MethodGet, AuditQueryRoute, "").Code)
	})
}

func TestAuditEntryByID(t *testing.T) {
	t.Parallel()
	p := &core.Principal{ID: "alice", Issuer: "gh-human"}
	aud := &fakeAuditor{entries: []core.Event{{ID: "e1", Action: core.ActionLeaseIssue, Outcome: core.OutcomeSuccess}}}

	t.Run("found", func(t *testing.T) {
		t.Parallel()
		srv := adminHandlerServer(t, p, true, aud, nil)
		rec := req(t, srv, http.MethodGet, "/v2/audit/e1", "session")
		require.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), `"e1"`)
		assert.Equal(t, "e1", aud.gotFilter.ID)
	})
	t.Run("not found -> 404", func(t *testing.T) {
		t.Parallel()
		empty := &fakeAuditor{}
		srv := adminHandlerServer(t, p, true, empty, nil)
		rec := req(t, srv, http.MethodGet, "/v2/audit/missing", "session")
		assert.Equal(t, http.StatusNotFound, rec.Code)
	})
	t.Run("unauthorized -> 403", func(t *testing.T) {
		t.Parallel()
		srv := adminHandlerServer(t, p, false, aud, nil)
		assert.Equal(t, http.StatusForbidden, req(t, srv, http.MethodGet, "/v2/audit/e1", "session").Code)
	})
}

func TestParseAuditFilter(t *testing.T) {
	t.Parallel()

	t.Run("maps all query params", func(t *testing.T) {
		t.Parallel()
		is := assert.New(t)

		q := url.Values{}
		q.Set("id", "e1")
		q.Set("request_id", "req1")
		q.Set("session_id", "sess1")
		q.Set("principal_id", "alice")
		q.Set("action", "lease.issue")
		q.Set("outcome", "denied")
		q.Set("fingerprint", "fp1")
		q.Set("since", "2026-01-01T00:00:00Z")
		q.Set("until", "2026-02-01T00:00:00Z")
		q.Set("limit", "10")

		f := parseAuditFilter(q)
		is.Equal("e1", f.ID)
		is.Equal("req1", f.RequestID)
		is.Equal("sess1", f.SessionID)
		is.Equal("alice", f.ActorID)
		is.Equal(core.ActionLeaseIssue, f.Action)
		is.Equal(core.OutcomeDenied, f.Outcome)
		is.Equal("fp1", f.Fingerprint)
		is.Equal(2026, f.Since.Year())
		is.Equal(time.February, f.Until.Month())
		is.Equal(10, f.Limit)
	})

	t.Run("empty query uses default limit and zero times", func(t *testing.T) {
		t.Parallel()
		is := assert.New(t)

		f := parseAuditFilter(url.Values{})
		is.Equal(50, f.Limit)
		is.True(f.Since.IsZero())
		is.True(f.Until.IsZero())
		is.Empty(f.Action)
	})
}

func TestTaskTrigger(t *testing.T) {
	t.Parallel()
	p := &core.Principal{ID: "alice", Issuer: "gh-human"}
	tm := tasks.NewManager(context.Background())
	tm.Register("sync", 0, func(ctx context.Context, logger logging.InternalLogger) error {
		return nil
	})

	srv := adminHandlerServer(t, p, true, &fakeAuditor{}, tm)

	assert.Equal(t, http.StatusAccepted, req(t, srv, http.MethodPost, "/v2/tasks/sync/trigger", "session").Code)
	assert.Equal(t, http.StatusNotFound, req(t, srv, http.MethodPost, "/v2/tasks/unknown/trigger", "session").Code)
}
