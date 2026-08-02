package source

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/darmiel/talmi/internal/config"
)

func TestLocalSourceLoad(t *testing.T) {
	t.Parallel()
	is := assert.New(t)

	dir := t.TempDir()
	for _, sub := range []string{"issuers.d", "realms.d", "rules.d"} {
		require.NoError(t, os.MkdirAll(filepath.Join(dir, sub), 0o755))
	}
	write := func(rel, content string) {
		require.NoError(t, os.WriteFile(filepath.Join(dir, rel), []byte(content), 0o600))
	}
	write("issuers.d/cc.yaml", "- name: concourse-prod\n  type: concourse-oidc\n")
	write("realms.d/gh.yaml", "- realm: ghes-corp\n  type: github-app\n  instances:\n    - name: gh-ro\n      app_id: 1\n")
	write("rules.d/prod.yaml", "- name: prod-ci\n  match:\n    issuer: concourse-prod\n    allow_empty: true\n  allow:\n    - resources: [\"ghes-corp:acme/*\"]\n      actions: [\"contents:read\"]\n")

	cfg := &config.Config{
		Issuers: config.Includes{Include: []string{"issuers.d/*.yaml"}},
		Realms:  config.Includes{Include: []string{"realms.d/*.yaml"}},
		Rules:   config.Includes{Include: []string{"rules.d/*.yaml"}},
	}

	sourced, revision, err := NewLocalSource(dir, cfg).Load(context.Background())
	require.NoError(t, err)
	is.Equal("local", revision)
	require.Len(t, sourced.Issuers, 1)
	is.Equal("concourse-prod", sourced.Issuers[0].Name)
	require.Len(t, sourced.Realms, 1)
	is.Equal("ghes-corp", sourced.Realms[0].Realm)
	require.Len(t, sourced.Realms[0].Instances, 1)
	require.Len(t, sourced.Rules, 1)
	is.Equal("prod-ci", sourced.Rules[0].Name)
}
