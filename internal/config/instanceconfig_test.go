package config

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/darmiel/talmi/internal/secret"
)

func TestDecodeInstanceConfig(t *testing.T) {
	t.Parallel()

	t.Run("github-app valid", func(t *testing.T) {
		t.Parallel()
		is := assert.New(t)
		got, err := DecodeInstanceConfig(KindGitHubApp, map[string]any{
			"app_id": 42, "private_key": "raw:pem", "server": "https://ghes/api/v3",
		})
		require.NoError(t, err)
		cfg, ok := got.(*GitHubAppConfig)
		require.True(t, ok, "expected *GitHubAppConfig, got %T", got)
		is.Equal(int64(42), cfg.AppID)
		is.Equal(secret.Ref("raw:pem"), cfg.PrivateKey)
		is.Equal("https://ghes/api/v3", cfg.Server)
	})

	t.Run("github-app unknown key is a hard error", func(t *testing.T) {
		t.Parallel()
		_, err := DecodeInstanceConfig(KindGitHubApp, map[string]any{"appid": 42, "private_key": "raw:pem"})
		require.Error(t, err)
		assert.ErrorContains(t, err, "appid")
	})

	t.Run("github-app missing creds fail Validate", func(t *testing.T) {
		t.Parallel()
		_, err := DecodeInstanceConfig(KindGitHubApp, map[string]any{"private_key": "raw:pem"})
		assert.Error(t, err, "missing app_id")
		_, err = DecodeInstanceConfig(KindGitHubApp, map[string]any{"app_id": 1})
		assert.Error(t, err, "missing private_key")
	})

	t.Run("artifactory valid", func(t *testing.T) {
		t.Parallel()
		is := assert.New(t)
		got, err := DecodeInstanceConfig(KindArtifactory, map[string]any{
			"admin_token": "raw:t", "groups": []any{"readers"},
		})
		require.NoError(t, err)
		cfg, ok := got.(*ArtifactoryConfig)
		require.True(t, ok, "expected *ArtifactoryConfig, got %T", got)
		is.Equal(secret.Ref("raw:t"), cfg.AdminToken)
		is.Equal([]string{"readers"}, cfg.Groups)
	})

	t.Run("artifactory missing groups fails Validate", func(t *testing.T) {
		t.Parallel()
		_, err := DecodeInstanceConfig(KindArtifactory, map[string]any{"admin_token": "raw:t"})
		assert.Error(t, err)
	})

	t.Run("talmi realm carries no instance config", func(t *testing.T) {
		t.Parallel()
		got, err := DecodeInstanceConfig("talmi", nil)
		require.NoError(t, err)
		assert.Nil(t, got, "realms without a provider backend decode to nil")
	})

	t.Run("strips inline name/type keys", func(t *testing.T) {
		t.Parallel()
		_, err := DecodeInstanceConfig(KindGitHubApp, map[string]any{
			"name": "gh-1", "type": "github-app", "app_id": 1, "private_key": "raw:k",
		})
		require.NoError(t, err, "inline name/type must not be treated as unknown keys")
	})
}

func TestInstanceTypes(t *testing.T) {
	t.Parallel()
	assert.Equal(t, []string{KindArtifactory, KindGitHubApp}, InstanceTypes())
}

func TestDecodeInstanceConfigTimeout(t *testing.T) {
	t.Parallel()

	t.Run("artifactory timeout string decodes to duration", func(t *testing.T) {
		t.Parallel()
		got, err := DecodeInstanceConfig(KindArtifactory, map[string]any{
			"admin_token": "raw:t", "groups": []any{"g"}, "timeout": "5s",
		})
		require.NoError(t, err)
		cfg, ok := got.(*ArtifactoryConfig)
		require.True(t, ok)
		assert.Equal(t, 5*time.Second, cfg.Timeout)
	})

	t.Run("github-app timeout string decodes to duration", func(t *testing.T) {
		t.Parallel()
		got, err := DecodeInstanceConfig(KindGitHubApp, map[string]any{
			"app_id": 1, "private_key": "raw:pem", "timeout": "10s",
		})
		require.NoError(t, err)
		cfg, ok := got.(*GitHubAppConfig)
		require.True(t, ok)
		assert.Equal(t, 10*time.Second, cfg.Timeout)
	})

	t.Run("negative timeout fails Validate", func(t *testing.T) {
		t.Parallel()
		_, err := DecodeInstanceConfig(KindArtifactory, map[string]any{
			"admin_token": "raw:t", "groups": []any{"g"}, "timeout": "-1s",
		})
		assert.Error(t, err)
	})
}
