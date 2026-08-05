package backend

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/darmiel/talmi/internal/config"
	"github.com/darmiel/talmi/internal/core"
	"github.com/darmiel/talmi/internal/realm"
)

func TestTypesAndLookup(t *testing.T) {
	t.Parallel()
	is := assert.New(t)

	is.ElementsMatch([]string{config.KindGitHubApp, config.KindArtifactory}, Types())

	_, ok := Lookup(config.KindGitHubApp)
	is.True(ok)
	_, ok = Lookup("gitlab")
	is.False(ok, "unknown backend must not resolve")
}

func TestBuildGitHubApp(t *testing.T) {
	t.Parallel()
	b, ok := Lookup(config.KindGitHubApp)
	require.True(t, ok)

	p, err := b.Build(BuildInput{Spec: config.ProviderSpec{
		Name:  "gh",
		Realm: "ghes-corp",
		Type:  config.KindGitHubApp,
		Config: &config.GitHubAppConfig{
			AppID: 1, PrivateKey: "raw:pem",
		},
	}})
	require.NoError(t, err)
	assert.Equal(t, "gh", p.Name())
	assert.Equal(t, "ghes-corp", p.Realm())
}

func TestBuildArtifactory(t *testing.T) {
	t.Parallel()
	b, ok := Lookup(config.KindArtifactory)
	require.True(t, ok)

	p, err := b.Build(BuildInput{Spec: config.ProviderSpec{
		Name:  "art",
		Realm: "art",
		Type:  config.KindArtifactory,
		Capability: config.CapabilityBlock{
			Resources: []string{"art:docker-*"}, MaxActions: []core.Action{"read"},
		},
		Config: &config.ArtifactoryConfig{
			AdminToken: "raw:tok", Groups: []string{"readers"}, BaseURL: "https://art",
		},
	}})
	require.NoError(t, err)
	assert.Equal(t, "art", p.Name())
}

// TestBackendsAgreeWithConfigAndRealm is the cross-package drift guard: every
// backend type must have a typed instance config (config) and realm semantics.
func TestBackendsAgreeWithConfigAndRealm(t *testing.T) {
	t.Parallel()
	is := assert.New(t)

	is.ElementsMatch(config.InstanceTypes(), Types(),
		"backend table and config.InstanceTypes() must list the same provider types")

	for _, ty := range Types() {
		b, ok := Lookup(ty)
		require.True(t, ok)
		require.NotNil(t, b.Semantics, "backend %q must carry semantics", ty)
		is.Equal(ty, b.Semantics.Kind())

		_, known := realm.SemanticsFor(ty)
		is.Truef(known, "realm.SemanticsFor(%q) must be known", ty)
	}
}
