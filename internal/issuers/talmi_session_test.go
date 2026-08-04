package issuers

import (
	"context"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/darmiel/talmi/internal/config"
	"github.com/darmiel/talmi/internal/core"
)

func TestNewTalmiSessionRequiresKey(t *testing.T) {
	t.Parallel()
	_, err := NewTalmiSessionIssuer("x", config.TalmiSessionConfig{}, nil)
	assert.Error(t, err)
}

func signHS256(t *testing.T, claims jwt.MapClaims, key []byte) string {
	t.Helper()
	s, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(key)
	require.NoError(t, err)
	return s
}

func TestTalmiSessionIssuer(t *testing.T) {
	t.Parallel()
	key := []byte("session-signing-key")
	signer, err := NewSessionSigner("HS256", key)
	require.NoError(t, err)
	iss, err := NewTalmiSessionIssuer("talmi-admins", config.TalmiSessionConfig{}, signer)
	require.NoError(t, err)
	assert.Equal(t, "talmi-admins", iss.Name())

	future := time.Now().Add(time.Hour).Unix()

	t.Run("valid session with claims", func(t *testing.T) {
		t.Parallel()
		is := assert.New(t)
		token := signHS256(t, jwt.MapClaims{
			"aud": TalmiSessionAudience, "sub": "alice", "exp": future,
			"origin_iss": "gh-human",
			"attrs":      map[string]any{"teams": []string{"acme/platform-admins"}},
		}, key)
		p, err := iss.Verify(context.Background(), token)
		require.NoError(t, err)
		is.Equal("alice", p.ID)
		is.Equal("gh-human", p.Issuer) // restored from origin_iss
		is.Contains(p.Attributes["teams"], "acme/platform-admins")
	})

	t.Run("wrong audience", func(t *testing.T) {
		t.Parallel()
		token := signHS256(t, jwt.MapClaims{"aud": "talmi-principal", "sub": "a", "exp": future}, key)
		_, err := iss.Verify(context.Background(), token)
		assert.Error(t, err)
	})

	t.Run("missing audience", func(t *testing.T) {
		t.Parallel()
		token := signHS256(t, jwt.MapClaims{"sub": "a", "exp": future}, key)
		_, err := iss.Verify(context.Background(), token)
		assert.Error(t, err)
	})

	t.Run("wrong key", func(t *testing.T) {
		t.Parallel()
		token := signHS256(t, jwt.MapClaims{"aud": TalmiSessionAudience, "sub": "a", "exp": future}, []byte("other"))
		_, err := iss.Verify(context.Background(), token)
		assert.Error(t, err)
	})

	t.Run("expired token", func(t *testing.T) {
		t.Parallel()
		token := signHS256(t, jwt.MapClaims{
			"aud": TalmiSessionAudience,
			"sub": "a",
			"exp": time.Now().Add(-time.Hour).Unix(),
		}, key)
		_, err := iss.Verify(context.Background(), token)
		assert.Error(t, err)
	})

	t.Run("alg confusion: RS256 token rejected", func(t *testing.T) {
		t.Parallel()
		// A token that claims a non-HMAC alg must be rejected by the HMAC-only keyfunc.
		tok := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{
			"aud": TalmiSessionAudience,
			"sub": "a",
			"exp": future,
		})
		s, err := tok.SignedString(jwt.UnsafeAllowNoneSignatureType)
		require.NoError(t, err)
		_, err = iss.Verify(context.Background(), s)
		assert.Error(t, err)
	})

	t.Run("not a jwt", func(t *testing.T) {
		t.Parallel()
		_, err := iss.Verify(context.Background(), "garbage")
		assert.Error(t, err)
	})
}

func TestIssueAndVerifySession(t *testing.T) {
	t.Parallel()
	key := []byte("k")
	signer, err := NewSessionSigner("HS256", key)
	require.NoError(t, err)
	iss, err := NewTalmiSessionIssuer("talmi-admins", config.TalmiSessionConfig{}, signer)
	require.NoError(t, err)

	p := &core.Principal{ID: "alice", Issuer: "gh-human", Attributes: map[string]any{"teams": []any{"acme/admins"}}}
	tok, exp, err := IssueSession(signer, p, time.Hour)
	require.NoError(t, err)
	assert.True(t, exp.After(time.Now()))

	got, err := iss.Verify(context.Background(), tok)
	require.NoError(t, err)
	assert.Equal(t, "alice", got.ID)
	assert.Equal(t, "gh-human", got.Issuer) // restored from origin_iss — admin rules match this
	assert.Contains(t, got.Attributes["teams"], "acme/admins")
}
