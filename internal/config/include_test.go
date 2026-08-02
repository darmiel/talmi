package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadSection(t *testing.T) {
	t.Parallel()
	is := assert.New(t)

	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "realms.d"), 0o755))
	write := func(name, content string) {
		require.NoError(t, os.WriteFile(filepath.Join(dir, "realms.d", name), []byte(content), 0o600))
	}
	write("02-corp.yaml", "- realm: ghes-corp\n  type: github-app\n  instances: []\n")
	write("01-dot.yaml", "- realm: github-com\n  type: github-app\n  instances: []\n")
	write("ignore.txt", "not yaml")

	blocks, err := LoadSection[RealmBlock](dir, []string{"realms.d/*.yaml"})
	require.NoError(t, err)
	require.Len(t, blocks, 2)
	// filename-sorted: 01 before 02
	is.Equal("github-com", blocks[0].Realm)
	is.Equal("ghes-corp", blocks[1].Realm)
}

func TestLoadSectionBadYAML(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "rules.d"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "rules.d", "x.yaml"), []byte("{not: valid: yaml:"), 0o600))
	_, err := LoadSection[RealmBlock](dir, []string{"rules.d/*.yaml"})
	assert.Error(t, err)
}

func TestLoadSectionNoMatches(t *testing.T) {
	t.Parallel()
	blocks, err := LoadSection[RealmBlock](t.TempDir(), []string{"realms.d/*.yaml"})
	assert.NoError(t, err)
	assert.Empty(t, blocks)
}
