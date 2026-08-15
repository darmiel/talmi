package github

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testAppKey returns a valid RSA private key in PEM so NewClient can sign the app JWT.
func testAppKey(t *testing.T) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
}

// nextLink builds a GitHub-style Link header pointing at page 2 of the current path.
//
//goland:noinspection HttpUrlsUsage
func nextLink(r *http.Request) string {
	u := "http://" + r.Host + r.URL.Path + "?page=2&per_page=100"
	return fmt.Sprintf("<%s>; rel=\"next\"", u)
}

// TestDiscoverViaAPIPaginates verifies that discovery reads every page of both
// installations and per-installation repositories, not just the first.
func TestDiscoverViaAPIPaginates(t *testing.T) {
	t.Parallel()
	is := assert.New(t)
	must := require.New(t)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		page := r.URL.Query().Get("page")
		w.Header().Set("Content-Type", "application/json")

		switch {
		// authenticated app: permissions -> max actions
		case strings.HasSuffix(r.URL.Path, "/app") && r.Method == http.MethodGet:
			_, _ = w.Write([]byte(`{"permissions":{"contents":"write"}}`))

		// installations, two pages: acme (1) then beta (2)
		case strings.HasSuffix(r.URL.Path, "/app/installations"):
			if page == "2" {
				_, _ = w.Write([]byte(`[{"id":2,"account":{"login":"beta"}}]`))
				return
			}
			w.Header().Set("Link", nextLink(r))
			_, _ = w.Write([]byte(`[{"id":1,"account":{"login":"acme"}}]`))

		// installation token minting for each installation
		case strings.HasSuffix(r.URL.Path, "/access_tokens") && r.Method == http.MethodPost:
			_, _ = w.Write([]byte(`{"token":"ghs_x","expires_at":"2999-01-01T00:00:00Z"}`))

		// repos for the installation, two pages
		case strings.HasSuffix(r.URL.Path, "/installation/repositories"):
			if page == "2" {
				_, _ = w.Write([]byte(`{"total_count":1,"repositories":[{"name":"repo-p2"}]}`))
				return
			}
			w.Header().Set("Link", nextLink(r))
			_, _ = w.Write([]byte(`{"total_count":1,"repositories":[{"name":"repo-p1"}]}`))

		default:
			t.Logf("unexpected request: %s %s", r.Method, r.URL.Path)
			http.Error(w, "unexpected", http.StatusNotFound)
		}
	}))
	defer ts.Close()

	p := &Provider{
		name:          "gh",
		realm:         "ghes-corp",
		appID:         1,
		privateKey:    testAppKey(t),
		serverBaseURL: ts.URL,
	}

	d, err := p.discoverViaAPI(context.Background())
	must.NoError(err)

	// both installation pages were read
	is.Equal(int64(1), d.installByOwner["acme"])
	is.Equal(int64(2), d.installByOwner["beta"], "second installations page must be read")

	// both repo pages were read for each installation
	is.ElementsMatch([]string{"repo-p1", "repo-p2"}, d.reposByOwner["acme"], "both repo pages must be read")
	is.ElementsMatch([]string{"repo-p1", "repo-p2"}, d.reposByOwner["beta"], "both repo pages must be read")
}
