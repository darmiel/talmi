package github

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRevokeDoesNotPanicOnTransportError_TALMI_H3(t *testing.T) {
	t.Parallel()

	// A reachable server so client construction succeeds; the request itself
	// fails because the context is already cancelled, yielding a *url.Error
	// (not a *github.ErrorResponse).
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	p, _ := newTestProvider(t, &discovered{})
	p.serverBaseURL = ts.URL

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // pre-cancel so the HTTP call returns context.Canceled

	require.NotPanics(t, func() {
		err := p.Revoke(ctx, "github-installation-1", "some-token")
		assert.Error(t, err, "a cancelled/transport error must be returned, not treated as success (TALMI-H3)")
	}, "revoke must not panic when the error is not a *github.ErrorResponse (TALMI-H3)")
}
