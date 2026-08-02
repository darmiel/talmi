package issuers

import (
	"context"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/darmiel/talmi/internal/config"
)

func TestOIDCIssuerVerify(t *testing.T) {
	t.Parallel()
	issuerURL, sign := newMockOIDCProvider(t)
	const clientID = "talmi-prod"

	iss, err := NewOIDCIssuer(context.Background(), config.IssuerBlock{
		Name:   "concourse",
		Config: map[string]any{"issuer_url": issuerURL, "client_id": clientID},
	})
	require.NoError(t, err)

	base := func() jwt.MapClaims {
		return jwt.MapClaims{
			"iss": issuerURL, "aud": clientID, "sub": "pipeline/deploy",
			"iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix(),
		}
	}

	t.Run("valid token", func(t *testing.T) {
		t.Parallel()
		is := assert.New(t)
		claims := base()
		claims["team"] = "platform"
		p, err := iss.Verify(context.Background(), sign(claims))
		require.NoError(t, err)
		is.Equal("pipeline/deploy", p.ID)
		is.Equal("concourse", p.Issuer)
		is.Equal("platform", p.Attributes["team"])
	})

	t.Run("wrong audience", func(t *testing.T) {
		t.Parallel()
		claims := base()
		claims["aud"] = "some-other-client"
		_, err := iss.Verify(context.Background(), sign(claims))
		assert.Error(t, err)
	})

	t.Run("expired token", func(t *testing.T) {
		t.Parallel()
		claims := base()
		claims["exp"] = time.Now().Add(-time.Hour).Unix()
		_, err := iss.Verify(context.Background(), sign(claims))
		assert.Error(t, err)
	})

	t.Run("signature from a different provider", func(t *testing.T) {
		t.Parallel()
		_, otherSign := newMockOIDCProvider(t)
		claims := base() // correct iss/aud, but signed by a key not in our JWKS
		_, err := iss.Verify(context.Background(), otherSign(claims))
		assert.Error(t, err)
	})
}

func TestNewOIDCIssuerValidation(t *testing.T) {
	t.Parallel()
	issuerURL, _ := newMockOIDCProvider(t)

	_, err := NewOIDCIssuer(context.Background(), config.IssuerBlock{
		Name:   "x",
		Config: map[string]any{"client_id": "c"},
	})
	assert.Error(t, err, "missing issuer_url")

	_, err = NewOIDCIssuer(context.Background(), config.IssuerBlock{
		Name:   "x",
		Config: map[string]any{"issuer_url": issuerURL},
	})
	assert.Error(t, err, "missing client_id")
}

func TestExtractIssuerURL(t *testing.T) {
	t.Parallel()

	t.Run("extracts iss", func(t *testing.T) {
		t.Parallel()
		tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"iss": "https://idp"}).SignedString([]byte("k"))
		require.NoError(t, err)
		url, err := ExtractIssuerURL(tok)
		require.NoError(t, err)
		assert.Equal(t, "https://idp", url)
	})

	t.Run("missing iss", func(t *testing.T) {
		t.Parallel()
		tok, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"sub": "x"}).SignedString([]byte("k"))
		_, err := ExtractIssuerURL(tok)
		assert.Error(t, err)
	})

	t.Run("not a jwt", func(t *testing.T) {
		t.Parallel()
		_, err := ExtractIssuerURL("not.a.jwt")
		assert.Error(t, err)
	})
}
