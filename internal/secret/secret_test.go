package secret

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResolveFile(t *testing.T) {
	t.Parallel()
	is := assert.New(t)

	dir := t.TempDir()
	path := filepath.Join(dir, "sec")
	require.NoError(t, os.WriteFile(path, []byte("file-value"), 0o600))

	got, err := Resolve(Ref("file:" + path))
	is.NoError(err)
	is.Equal([]byte("file-value"), got)

	_, err = Resolve(Ref("file:" + filepath.Join(dir, "missing")))
	is.Error(err)
}

func TestResolveEnv(t *testing.T) {
	is := assert.New(t)

	t.Setenv("TALMI_TEST_SECRET", "env-value")
	got, err := ResolveString("env:TALMI_TEST_SECRET")
	is.NoError(err)
	is.Equal("env-value", got)

	_, err = Resolve("env:TALMI_DEFINITELY_UNSET_VAR")
	is.Error(err)
}

func TestResolveRaw(t *testing.T) {
	t.Parallel()
	got, err := ResolveString("raw:literal-secret")
	assert.NoError(t, err)
	assert.Equal(t, "literal-secret", got)
}

func TestResolveErrors(t *testing.T) {
	t.Parallel()
	is := assert.New(t)

	// missing scheme: must NOT echo the (possibly secret) value
	_, err := Resolve("supersecretvalue")
	is.Error(err)
	is.NotContains(err.Error(), "supersecretvalue")

	_, err = Resolve("vault:some/path")
	is.Error(err)
	is.Contains(err.Error(), "vault") // scheme name is safe to surface
}
