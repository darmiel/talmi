package issuers

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
)

// newMockOIDCProvider spins an OIDC discovery + JWKS server and returns its
// issuer URL and a signer for RS256 ID tokens.
func newMockOIDCProvider(t *testing.T) (issuerURL string, sign func(jwt.MapClaims) string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	const kid = "test-key"

	jwks := map[string]any{
		"keys": []any{
			map[string]any{
				"kty": "RSA", "kid": kid, "use": "sig", "alg": "RS256",
				"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
				"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
			},
		},
	}

	var srv *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                srv.URL,
			"jwks_uri":                              srv.URL + "/jwks",
			"authorization_endpoint":                srv.URL + "/auth",
			"token_endpoint":                        srv.URL + "/token",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(jwks)
	})
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	sign = func(claims jwt.MapClaims) string {
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		tok.Header["kid"] = kid
		s, err := tok.SignedString(key)
		require.NoError(t, err)
		return s
	}
	return srv.URL, sign
}

// newMockGitHubServer serves the GHES API endpoints used by GitHubOAuthIssuer,
// including a paginated /user/teams. Returns the server base URL.
func newMockGitHubServer(t *testing.T, failUser bool) string {
	t.Helper()
	var srv *httptest.Server
	mux := http.NewServeMux()

	mux.HandleFunc("/api/v3/user", func(w http.ResponseWriter, _ *http.Request) {
		if failUser {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"login": "alice"})
	})
	mux.HandleFunc("/api/v3/user/teams", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("page") == "2" {
			_ = json.NewEncoder(w).Encode([]map[string]any{
				{"slug": "deployers", "organization": map[string]any{"login": "acme"}},
			})
			return
		}
		w.Header().Set("Link", fmt.Sprintf(`<%s/api/v3/user/teams?page=2>; rel="next"`, srv.URL))
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{"slug": "admins", "organization": map[string]any{"login": "acme"}},
		})
	})

	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL
}
