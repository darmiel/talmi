package issuers

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/darmiel/talmi/internal/config"
	"github.com/darmiel/talmi/internal/secret"
)

// rsaJWKSJSON builds a standard JWKS document (kty/n/e) for an RSA public key,
// matching what a real jwks_uri serves.
func rsaJWKSJSON(t *testing.T, pub *rsa.PublicKey) []byte {
	t.Helper()
	jwks := map[string]any{
		"keys": []any{
			map[string]any{
				"kty": "RSA", "kid": "k1", "use": "sig", "alg": "RS256",
				"n": base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
				"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
			},
		},
	}
	b, err := json.Marshal(jwks)
	require.NoError(t, err)
	return b
}

func signRS(t *testing.T, key *rsa.PrivateKey, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = "k1"
	s, err := tok.SignedString(key)
	require.NoError(t, err)
	return s
}

func TestParseJWKS(t *testing.T) {
	t.Parallel()
	is := assert.New(t)
	must := require.New(t)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	must.NoError(err)

	keys, err := parseJWKS(rsaJWKSJSON(t, &key.PublicKey))
	must.NoError(err)
	must.Len(keys, 1)
	_, ok := keys[0].(*rsa.PublicKey)
	is.True(ok, "public key extracted")

	_, err = parseJWKS([]byte(`{"keys":[]}`))
	is.Error(err, "empty jwks must error")
	_, err = parseJWKS([]byte(`not json`))
	is.Error(err)
}

func TestOIDCStaticKeysOffline(t *testing.T) {
	t.Parallel()
	is := assert.New(t)
	must := require.New(t)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	must.NoError(err)

	iss, err := NewOIDCIssuer(context.Background(), "ci", config.OIDCConfig{
		IssuerURL: "https://airgap.invalid", // must never be dialed
		ClientID:  "my-aud",
		JWKS:      secret.Ref("raw:" + string(rsaJWKSJSON(t, &key.PublicKey))),
	})
	must.NoError(err, "static construction must not touch the network")

	exp := time.Now().Add(time.Hour).Unix()
	good := signRS(t, key, jwt.MapClaims{"iss": "https://airgap.invalid", "aud": "my-aud", "sub": "svc", "exp": exp})
	p, err := iss.Verify(context.Background(), good)
	must.NoError(err)
	is.Equal("svc", p.ID)

	other, err := rsa.GenerateKey(rand.Reader, 2048)
	must.NoError(err)
	bad := signRS(t, other, jwt.MapClaims{"iss": "https://airgap.invalid", "aud": "my-aud", "sub": "x", "exp": exp})
	_, err = iss.Verify(context.Background(), bad)
	is.Error(err, "token signed by an unknown key must be rejected")

	wrongIss := signRS(t, key, jwt.MapClaims{"iss": "https://evil", "aud": "my-aud", "sub": "x", "exp": exp})
	_, err = iss.Verify(context.Background(), wrongIss)
	is.Error(err, "wrong iss must be rejected")
}

func TestOIDCMirrorURLSkipsDiscovery(t *testing.T) {
	t.Parallel()
	is := assert.New(t)
	must := require.New(t)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	must.NoError(err)

	var discoveryHit, jwksHit bool
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		discoveryHit = true
		http.Error(w, "no discovery", http.StatusInternalServerError)
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		jwksHit = true
		_, _ = w.Write(rsaJWKSJSON(t, &key.PublicKey))
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	iss, err := NewOIDCIssuer(context.Background(), "ci", config.OIDCConfig{
		IssuerURL: ts.URL,
		ClientID:  "my-aud",
		JWKSURL:   ts.URL + "/jwks",
	})
	must.NoError(err)

	tok := signRS(t, key, jwt.MapClaims{
		"iss": ts.URL,
		"aud": "my-aud",
		"sub": "svc",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	_, err = iss.Verify(context.Background(), tok)
	must.NoError(err)
	is.False(discoveryHit, "discovery must be skipped")
	is.True(jwksHit, "keys fetched from the mirror URL")
}
