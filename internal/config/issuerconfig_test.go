package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDecodeIssuerConfig(t *testing.T) {
	t.Parallel()

	t.Run("oidc valid", func(t *testing.T) {
		t.Parallel()
		is := assert.New(t)
		got, err := DecodeIssuerConfig(IssuerBlock{
			Name: "cc", Type: "oidc",
			Config: map[string]any{"issuer_url": "https://idp.example.com", "client_id": "c"},
		})
		require.NoError(t, err)
		cfg, ok := got.(*OIDCConfig)
		require.True(t, ok, "expected *OIDCConfig, got %T", got)
		is.Equal("https://idp.example.com", cfg.IssuerURL)
		is.Equal("c", cfg.ClientID)
	})

	t.Run("oidc unknown key is a hard error", func(t *testing.T) {
		t.Parallel()
		_, err := DecodeIssuerConfig(IssuerBlock{
			Name: "cc", Type: "oidc",
			Config: map[string]any{"issuerurl": "https://idp.example.com", "client_id": "c"},
		})
		require.Error(t, err)
		assert.ErrorContains(t, err, "issuerurl", "the error must name the offending unknown key")
	})

	t.Run("oidc missing client_id fails Validate", func(t *testing.T) {
		t.Parallel()
		_, err := DecodeIssuerConfig(IssuerBlock{
			Name: "cc", Type: "oidc",
			Config: map[string]any{"issuer_url": "https://idp.example.com"},
		})
		require.Error(t, err)
		assert.ErrorContains(t, err, "client_id")
	})

	t.Run("static valid nested token_map", func(t *testing.T) {
		t.Parallel()
		is := assert.New(t)
		got, err := DecodeIssuerConfig(IssuerBlock{
			Name: "ci", Type: "static",
			Config: map[string]any{
				"token_map": map[string]any{
					"raw-tok": map[string]any{"sub": "svc", "team": "platform"},
				},
			},
		})
		require.NoError(t, err)
		cfg, ok := got.(*StaticConfig)
		require.True(t, ok, "expected *StaticConfig, got %T", got)
		is.Equal("svc", cfg.TokenMap["raw-tok"]["sub"])
		is.Equal("platform", cfg.TokenMap["raw-tok"]["team"])
	})

	t.Run("static unknown key is a hard error", func(t *testing.T) {
		t.Parallel()
		_, err := DecodeIssuerConfig(IssuerBlock{
			Name: "ci", Type: "static",
			Config: map[string]any{"tokenmap": map[string]any{}},
		})
		require.Error(t, err)
		assert.ErrorContains(t, err, "tokenmap")
	})

	t.Run("github-oauth valid", func(t *testing.T) {
		t.Parallel()
		got, err := DecodeIssuerConfig(IssuerBlock{
			Name: "gh-human", Type: "github-oauth",
			Config: map[string]any{"server": "https://ghes/api/v3"},
		})
		require.NoError(t, err)
		cfg, ok := got.(*GitHubOAuthConfig)
		require.True(t, ok, "expected *GitHubOAuthConfig, got %T", got)
		assert.Equal(t, "https://ghes/api/v3", cfg.Server)
	})

	t.Run("github-oauth unknown key is a hard error", func(t *testing.T) {
		t.Parallel()
		_, err := DecodeIssuerConfig(IssuerBlock{
			Name: "gh-human", Type: "github-oauth",
			Config: map[string]any{"srv": "https://ghes"},
		})
		require.Error(t, err)
		assert.ErrorContains(t, err, "srv")
	})

	t.Run("talmi-session takes no config", func(t *testing.T) {
		t.Parallel()
		got, err := DecodeIssuerConfig(IssuerBlock{Name: "admins", Type: "talmi-session"})
		require.NoError(t, err)
		_, ok := got.(*TalmiSessionConfig)
		assert.True(t, ok, "expected *TalmiSessionConfig, got %T", got)
	})

	t.Run("talmi-session unknown key is a hard error", func(t *testing.T) {
		t.Parallel()
		_, err := DecodeIssuerConfig(IssuerBlock{
			Name: "admins", Type: "talmi-session",
			Config: map[string]any{"key": "should-not-be-here"},
		})
		require.Error(t, err)
		assert.ErrorContains(t, err, "key")
	})

	t.Run("unknown issuer type", func(t *testing.T) {
		t.Parallel()
		_, err := DecodeIssuerConfig(IssuerBlock{Name: "x", Type: "mystery"})
		require.Error(t, err)
		assert.ErrorContains(t, err, "unknown issuer type")
	})
}
