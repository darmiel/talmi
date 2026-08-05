package source

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/darmiel/talmi/internal/config"
)

func cfgWithGitHub(ref string) *config.Config {
	return &config.Config{
		ConfigSource: &config.SourceConfig{
			GitHub: &config.GitHubSource{
				Owner:      "acme",
				Repo:       "infra",
				Ref:        ref,
				PrivateKey: "raw:dummy",
			},
		},
	}
}

func TestPlan(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		cfg      *config.Config
		opts     Options
		wantKind sourceKind
		wantRef  string
		wantErr  bool
	}{
		{
			name:     "github configured, no flags -> github with configured ref",
			cfg:      cfgWithGitHub("main"),
			opts:     Options{},
			wantKind: kindGitHub,
			wantRef:  "main",
		},
		{
			name:     "github configured, ref override -> github with override",
			cfg:      cfgWithGitHub("main"),
			opts:     Options{Ref: "feature/x"},
			wantKind: kindGitHub,
			wantRef:  "feature/x",
		},
		{
			name:     "github configured, force local -> local",
			cfg:      cfgWithGitHub("main"),
			opts:     Options{ForceLocal: true},
			wantKind: kindLocal,
		},
		{
			name:     "no github source, no ref -> local",
			cfg:      &config.Config{},
			opts:     Options{},
			wantKind: kindLocal,
		},
		{
			name:    "no github source, ref set -> error",
			cfg:     &config.Config{},
			opts:    Options{Ref: "feature/x"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			kind, ref, err := plan(tt.cfg, tt.opts)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantKind, kind)
			assert.Equal(t, tt.wantRef, ref)
		})
	}
}

func TestResolve(t *testing.T) {
	t.Parallel()

	t.Run("local when no github source", func(t *testing.T) {
		t.Parallel()
		src, err := Resolve(&config.Config{}, "/tmp/base", Options{})
		require.NoError(t, err)
		assert.IsType(t, &LocalSource{}, src)
	})

	t.Run("github when configured", func(t *testing.T) {
		t.Parallel()
		src, err := Resolve(cfgWithGitHub("main"), "/tmp/base", Options{})
		require.NoError(t, err)
		assert.IsType(t, &GitHubSource{}, src)
	})

	t.Run("force local overrides github", func(t *testing.T) {
		t.Parallel()
		src, err := Resolve(cfgWithGitHub("main"), "/tmp/base", Options{ForceLocal: true})
		require.NoError(t, err)
		assert.IsType(t, &LocalSource{}, src)
	})

	t.Run("ref without remote source errors", func(t *testing.T) {
		t.Parallel()
		_, err := Resolve(&config.Config{}, "/tmp/base", Options{Ref: "feature/x"})
		require.Error(t, err)
	})
}
