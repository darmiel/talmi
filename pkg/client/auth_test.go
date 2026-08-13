package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestExchangeSessionUsesGitHubTokenNotStoredSession guards against the client
// overwriting an explicit per-request Authorization header with its stored
// session token. Login must send the GitHub token to the server, even when a
// (possibly stale) Talmi session is already saved on the client.
func TestExchangeSessionUsesGitHubTokenNotStoredSession(t *testing.T) {
	t.Parallel()
	is := assert.New(t)
	must := require.New(t)

	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		_ = json.NewEncoder(w).Encode(SessionResponse{Token: "new-session-jwt"})
	}))
	defer srv.Close()

	c := New(srv.URL, WithAuthToken("stale-talmi-session"))
	_, _, err := c.ExchangeSession(context.Background(), "ghes-oauth-token")
	must.NoError(err)

	is.Equal("Bearer ghes-oauth-token", gotAuth,
		"login must send the GitHub token, not the stored session")
}
