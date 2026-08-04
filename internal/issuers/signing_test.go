package issuers

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testECPrivateKeyPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
}

func TestSessionSignerRoundTrip(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		alg  string
		key  func(*testing.T) []byte
	}{
		{"ES256", "ES256", testECPrivateKeyPEM},
		{"HS256", "HS256", func(*testing.T) []byte { return []byte("shhh-super-secret") }},
		{"empty defaults to ES256", "", testECPrivateKeyPEM},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			is := assert.New(t)

			signer, err := NewSessionSigner(tc.alg, tc.key(t))
			require.NoError(t, err)

			signed, err := signer.Sign(jwt.MapClaims{
				"sub": "alice",
				"exp": time.Now().Add(time.Hour).Unix(),
			})
			require.NoError(t, err)

			claims := jwt.MapClaims{}
			parsed, err := jwt.ParseWithClaims(signed, claims, signer.keyfunc)
			require.NoError(t, err)
			is.True(parsed.Valid)
			is.Equal("alice", claims["sub"])
		})
	}
}

func TestNewSessionSignerRejectsBadInput(t *testing.T) {
	t.Parallel()
	is := assert.New(t)

	_, err := NewSessionSigner("ES256", []byte("not-a-pem-key"))
	is.Error(err, "ES256 with a non-PEM key must fail")

	_, err = NewSessionSigner("HS256", nil)
	is.Error(err, "HS256 with an empty secret must fail")

	_, err = NewSessionSigner("RS512", []byte("x"))
	is.Error(err, "unsupported algorithm must fail")
}

// TestSessionSignerRejectsAlgConfusion ensures a token signed with a different
// algorithm cannot be verified (alg-confusion / downgrade protection).
func TestSessionSignerRejectsAlgConfusion(t *testing.T) {
	t.Parallel()

	es, err := NewSessionSigner("ES256", testECPrivateKeyPEM(t))
	require.NoError(t, err)

	// Forge an HS256 token and try to verify it against the ES256 signer.
	forged, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"sub": "attacker"}).
		SignedString([]byte("guessed"))
	require.NoError(t, err)

	_, err = jwt.ParseWithClaims(forged, jwt.MapClaims{}, es.keyfunc)
	assert.Error(t, err, "ES256 signer must reject an HS256 token")
}
