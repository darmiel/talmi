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

func TestBuildRegistryTypes(t *testing.T) {
	t.Parallel()
	is := assert.New(t)

	blocks := []config.IssuerBlock{
		{
			Name:   "s",
			Type:   "static",
			Config: map[string]any{"token_map": map[string]any{"tok": map[string]any{"sub": "x"}}},
		},
		{Name: "gh-human", Type: "github-oauth", Config: map[string]any{"server": "https://ghes/api/v3"}},
		{Name: "talmi-admins", Type: "talmi-session"},
	}
	signer, err := NewSessionSigner("HS256", []byte("key"))
	require.NoError(t, err)
	reg, err := BuildRegistry(context.Background(), blocks, signer)
	require.NoError(t, err)

	for _, name := range []string{"s", "gh-human", "talmi-admins"} {
		_, ok := reg.Get(name)
		is.True(ok, "issuer %q should be present", name)
	}
	_, ok := reg.Get("nonexistent")
	is.False(ok)

	known := reg.KnownIssuers()
	is.Len(known, 3)
}

func TestBuildRegistryErrors(t *testing.T) {
	t.Parallel()

	t.Run("unknown type", func(t *testing.T) {
		t.Parallel()
		_, err := BuildRegistry(context.Background(), []config.IssuerBlock{{Name: "x", Type: "mystery"}}, nil)
		assert.Error(t, err)
	})
	t.Run("missing name", func(t *testing.T) {
		t.Parallel()
		_, err := BuildRegistry(context.Background(), []config.IssuerBlock{{Type: "static"}}, nil)
		assert.Error(t, err)
	})
	t.Run("talmi-session without key", func(t *testing.T) {
		t.Parallel()
		_, err := BuildRegistry(context.Background(), []config.IssuerBlock{{Name: "s", Type: "talmi-session"}}, nil)
		assert.Error(t, err)
	})
}

func TestRegistryIdentifyIssuer(t *testing.T) {
	t.Parallel()
	issuerURL, sign := newMockOIDCProvider(t)

	blocks := []config.IssuerBlock{
		{Name: "oidc-cc", Type: "oidc", Config: map[string]any{"issuer_url": issuerURL, "client_id": "c"}},
		{
			Name:   "static-ci",
			Type:   "static",
			Config: map[string]any{"token_map": map[string]any{"raw-tok": map[string]any{"sub": "x"}}},
		},
	}
	reg, err := BuildRegistry(context.Background(), blocks, nil)
	require.NoError(t, err)

	t.Run("routes JWT by iss url", func(t *testing.T) {
		t.Parallel()
		token := sign(jwt.MapClaims{"iss": issuerURL, "aud": "c", "sub": "s", "exp": time.Now().Add(time.Hour).Unix()})
		iss, err := reg.IdentifyIssuer(token)
		require.NoError(t, err)
		assert.Equal(t, "oidc-cc", iss.Name())
	})

	t.Run("routes raw token to static issuer", func(t *testing.T) {
		t.Parallel()
		iss, err := reg.IdentifyIssuer("raw-tok")
		require.NoError(t, err)
		assert.Equal(t, "static-ci", iss.Name())
	})

	t.Run("unknown JWT issuer url", func(t *testing.T) {
		t.Parallel()
		token := sign(jwt.MapClaims{"iss": "https://unknown", "sub": "s"})
		_, err := reg.IdentifyIssuer(token)
		assert.Error(t, err)
	})

	t.Run("unknown raw token", func(t *testing.T) {
		t.Parallel()
		_, err := reg.IdentifyIssuer("not-registered")
		assert.Error(t, err)
	})
}
