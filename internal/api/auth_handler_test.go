package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/darmiel/talmi/internal/core"
	"github.com/darmiel/talmi/internal/issuers"
)

func mustHS256Signer() *issuers.SessionSigner {
	s, err := issuers.NewSessionSigner("HS256", []byte("session-key"))
	if err != nil {
		panic(err)
	}
	return s
}

type fakeIssuer struct {
	principal *core.Principal
	err       error
}

func (fakeIssuer) Name() string { return "gh-human" }
func (f fakeIssuer) Verify(context.Context, string) (*core.Principal, error) {
	return f.principal, f.err
}

func adminServer(principal *core.Principal, verifyErr error, authorized bool) *Server {
	admin := AdminConfig{
		LoginIssuer:   func() (core.Issuer, bool) { return fakeIssuer{principal: principal, err: verifyErr}, true },
		SessionSigner: mustHS256Signer(),
		SessionTTL:    time.Hour,
		Authorize: func(*core.Principal, []core.ResourceRequest) core.Decision {
			return core.Decision{Authorized: authorized}
		},
	}
	return NewServer(func() TokenService { return nil }, WithAdmin(admin))
}

func postLogin(t *testing.T, srv *Server, auth string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, LoginRoute, nil)
	if auth != "" {
		req.Header.Set("Authorization", "Bearer "+auth)
	}
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	return rec
}

func TestHandleLogin(t *testing.T) {
	t.Parallel()
	p := &core.Principal{ID: "alice", Issuer: "gh-human", Attributes: map[string]any{"teams": []any{"acme/admins"}}}

	t.Run("authorized admin gets a session", func(t *testing.T) {
		t.Parallel()
		rec := postLogin(t, adminServer(p, nil, true), "gh-oauth-token")
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), `"token"`)
	})
	t.Run("not an admin -> 403", func(t *testing.T) {
		t.Parallel()
		rec := postLogin(t, adminServer(p, nil, false), "gh-oauth-token")
		assert.Equal(t, http.StatusForbidden, rec.Code)
	})
	t.Run("bad ghes token -> 401", func(t *testing.T) {
		t.Parallel()
		rec := postLogin(t, adminServer(nil, errAuth, true), "bad")
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})
	t.Run("missing token -> 401", func(t *testing.T) {
		t.Parallel()
		rec := postLogin(t, adminServer(p, nil, true), "")
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})
}

var errAuth = assertError()

func assertError() error { return &assertErr{} }

type assertErr struct{}

func (*assertErr) Error() string { return "verify failed" }
