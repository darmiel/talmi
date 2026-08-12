package api

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/darmiel/talmi/internal/audit"
	"github.com/darmiel/talmi/internal/core"
	"github.com/darmiel/talmi/internal/logging"
	"github.com/darmiel/talmi/internal/tasks"
)

func recorderWithCapture() (*audit.Recorder, *fakeAuditor) {
	a := &fakeAuditor{}
	return audit.NewRecorder(a), a
}

func TestLoginEmitsAuditEvent(t *testing.T) {
	t.Parallel()
	p := &core.Principal{ID: "alice", Issuer: "gh-human", Attributes: map[string]any{"teams": []any{"acme/admins"}}}

	t.Run("success emits session.login/success with actor and session id", func(t *testing.T) {
		t.Parallel()
		is := assert.New(t)
		must := require.New(t)

		rec, aud := recorderWithCapture()
		srv := NewServer(func() TokenService { return nil },
			WithRecorder(func() *audit.Recorder { return rec }),
			WithAdmin(AdminConfig{
				LoginIssuer:   func() (core.Issuer, bool) { return fakeIssuer{principal: p}, true },
				SessionSigner: mustHS256Signer(),
				SessionTTL:    time.Hour,
				Authorize: func(*core.Principal, []core.ResourceRequest) core.Decision {
					return core.Decision{Authorized: true}
				},
			}))

		resp := postLogin(t, srv, "gh-oauth-token")
		must.Equal(http.StatusOK, resp.Code)

		must.Len(aud.logged, 1)
		e := aud.logged[0]
		is.Equal(core.ActionSessionLogin, e.Action)
		is.Equal(core.OutcomeSuccess, e.Outcome)
		must.NotNil(e.Actor)
		is.Equal("alice", e.Actor.ID)
		is.NotEmpty(e.SessionID, "the login event carries the new jti as session id")
	})

	t.Run("verification failure emits session.login/failure", func(t *testing.T) {
		t.Parallel()
		is := assert.New(t)
		must := require.New(t)

		rec, aud := recorderWithCapture()
		srv := NewServer(func() TokenService { return nil },
			WithRecorder(func() *audit.Recorder { return rec }),
			WithAdmin(AdminConfig{
				LoginIssuer:   func() (core.Issuer, bool) { return fakeIssuer{err: errAuth}, true },
				SessionSigner: mustHS256Signer(),
				SessionTTL:    time.Hour,
				Authorize: func(*core.Principal, []core.ResourceRequest) core.Decision {
					return core.Decision{Authorized: true}
				},
			}))

		resp := postLogin(t, srv, "bad")
		must.Equal(http.StatusUnauthorized, resp.Code)

		must.Len(aud.logged, 1)
		is.Equal(core.ActionSessionLogin, aud.logged[0].Action)
		is.Equal(core.OutcomeFailure, aud.logged[0].Outcome)
	})
}

func TestAuthzDeniedEmitsAuditEvent(t *testing.T) {
	t.Parallel()
	is := assert.New(t)
	must := require.New(t)

	p := &core.Principal{ID: "alice", Issuer: "gh-human"}
	rec, aud := recorderWithCapture()
	srv := NewServer(func() TokenService { return nil },
		WithRecorder(func() *audit.Recorder { return rec }),
		WithAdmin(AdminConfig{
			SessionIssuer: func() (core.Issuer, bool) { return fakeIssuer{principal: p}, true },
			Authorize: func(*core.Principal, []core.ResourceRequest) core.Decision {
				return core.Decision{Authorized: false}
			},
			SessionTTL: time.Hour,
		}))

	resp := req(t, srv, http.MethodGet, AuditQueryRoute, "session")
	must.Equal(http.StatusForbidden, resp.Code)

	must.Len(aud.logged, 1)
	is.Equal(core.ActionAuthzDenied, aud.logged[0].Action)
	is.Equal(core.OutcomeDenied, aud.logged[0].Outcome)
}

func TestTaskTriggerEmitsAuditEvent(t *testing.T) {
	t.Parallel()
	is := assert.New(t)
	must := require.New(t)

	p := &core.Principal{ID: "alice", Issuer: "gh-human"}
	tm := tasks.NewManager(context.Background())
	tm.Register("sync", 0, func(context.Context, logging.InternalLogger) error { return nil })

	rec, aud := recorderWithCapture()
	srv := NewServer(func() TokenService { return nil },
		WithRecorder(func() *audit.Recorder { return rec }),
		WithAdmin(AdminConfig{
			SessionIssuer: func() (core.Issuer, bool) { return fakeIssuer{principal: p}, true },
			Authorize: func(*core.Principal, []core.ResourceRequest) core.Decision {
				return core.Decision{Authorized: true}
			},
			Tasks:      tm,
			SessionTTL: time.Hour,
		}))

	resp := req(t, srv, http.MethodPost, "/v2/tasks/sync/trigger", "session")
	must.Equal(http.StatusAccepted, resp.Code)

	must.Len(aud.logged, 1)
	e := aud.logged[0]
	is.Equal(core.ActionTaskTrigger, e.Action)
	is.Equal(core.OutcomeSuccess, e.Outcome)
	is.Equal("sync", e.Metadata["task"])
}

func TestWebhookEmitsAuditEvent(t *testing.T) {
	t.Parallel()
	is := assert.New(t)
	must := require.New(t)

	secret := []byte("s")
	body := []byte(`{"ref":"main"}`)
	rec, aud := recorderWithCapture()
	srv := NewServer(func() TokenService { return nil },
		WithRecorder(func() *audit.Recorder { return rec }),
		WithGitHubWebhook(secret, func(context.Context) error { return nil }))

	r := httptest.NewRequest(http.MethodPost, WebhookGitHubRoute, bytes.NewReader(body))
	r.Header.Set("X-Hub-Signature-256", sign(secret, body))
	resp := httptest.NewRecorder()
	srv.Routes().ServeHTTP(resp, r)
	must.Equal(http.StatusOK, resp.Code)

	must.Len(aud.logged, 1)
	is.Equal(core.ActionWebhookReceived, aud.logged[0].Action)
	is.Equal(core.OutcomeSuccess, aud.logged[0].Outcome)
}
