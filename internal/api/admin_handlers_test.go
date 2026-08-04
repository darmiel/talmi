package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/darmiel/talmi/internal/core"
	"github.com/darmiel/talmi/internal/logging"
	"github.com/darmiel/talmi/internal/tasks"
)

type fakeAuditor struct {
	entries   []core.AuditEntry
	gotFilter core.AuditFilter
}

func (a *fakeAuditor) Log(context.Context, core.AuditEntry) error { return nil }
func (a *fakeAuditor) Query(_ context.Context, f core.AuditFilter) ([]core.AuditEntry, error) {
	a.gotFilter = f
	return a.entries, nil
}
func (a *fakeAuditor) Close() error { return nil }

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
	aud := &fakeAuditor{entries: []core.AuditEntry{{ID: "l1", Action: "lease.issue", Success: true}}}

	t.Run("authorized returns entries and parses filter", func(t *testing.T) {
		t.Parallel()
		srv := adminHandlerServer(t, p, true, aud, nil)
		rec := req(t, srv, http.MethodGet, AuditQueryRoute+"?action=lease.issue&limit=10", "session")
		require.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), `"l1"`)
		assert.Equal(t, "lease.issue", aud.gotFilter.Action)
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
