package runtime

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/darmiel/talmi/internal/config"
	"github.com/darmiel/talmi/internal/core"
)

func TestBuildRealms(t *testing.T) {
	t.Parallel()
	reg, err := buildRealms([]config.RealmBlock{
		{Realm: "ghes-corp", Type: "github-app"},
		{Realm: "art", Type: "artifactory"},
		{Realm: "talmi", Type: "talmi"},
	})
	require.NoError(t, err)
	for _, name := range []string{"ghes-corp", "art", "talmi"} {
		_, ok := reg.Get(name)
		assert.True(t, ok, "realm %q", name)
	}

	_, err = buildRealms([]config.RealmBlock{{Realm: "x", Type: "mystery"}})
	assert.Error(t, err)
}

func TestBuildProviders(t *testing.T) {
	t.Parallel()

	t.Run("real providers construct", func(t *testing.T) {
		t.Parallel()
		specs := []config.ProviderSpec{
			{
				Name: "gh", Realm: "ghes-corp", Type: "github-app",
				Config: &config.GitHubAppConfig{AppID: 1, PrivateKey: "raw:dummy-pem"},
			},
			{
				Name: "art", Realm: "art", Type: "artifactory",
				Config: &config.ArtifactoryConfig{AdminToken: "raw:tok", Groups: []string{"g"}, BaseURL: "https://art"},
			},
		}
		ps, descs, err := buildProviders(specs, false)
		require.NoError(t, err)
		require.Len(t, ps, 2)
		assert.Equal(t, "gh", ps[0].Name())
		assert.Equal(t, "art", ps[1].Name())

		require.Len(t, descs, 2, "descriptors are index-aligned with providers")
		assert.Equal(t, ProviderDescriptor{
			Name:  "gh",
			Realm: "ghes-corp",
			Type:  "github-app",
			Mode:  descs[0].Mode,
		}, descs[0])
		assert.Equal(t, "art", descs[1].Name)
		assert.Equal(t, "artifactory", descs[1].Type)
		assert.NotEmpty(t, descs[0].Mode)
		assert.NotEmpty(t, descs[1].Mode)
	})

	t.Run("dev mode yields stubs", func(t *testing.T) {
		t.Parallel()
		specs := []config.ProviderSpec{
			{
				Name: "gh", Realm: "ghes-corp", Type: "github-app",
				Capability: config.CapabilityBlock{
					Resources:  []string{"ghes-corp:acme/*"},
					MaxActions: []core.Action{"contents:read"},
				},
			},
		}
		ps, descs, err := buildProviders(specs, true)
		require.NoError(t, err)
		require.Len(t, ps, 1)
		caps, err := ps[0].Capabilities(context.Background())
		require.NoError(t, err)
		assert.Equal(t, []string{"ghes-corp:acme/*"}, caps.Resources)

		require.Len(t, descs, 1)
		assert.Equal(t, "gh", descs[0].Name)
		assert.Equal(t, "github-app", descs[0].Type)
	})

	t.Run("unknown type", func(t *testing.T) {
		t.Parallel()
		_, _, err := buildProviders([]config.ProviderSpec{{Name: "x", Type: "weird"}}, false)
		assert.Error(t, err)
	})

	t.Run("bad secret ref", func(t *testing.T) {
		t.Parallel()
		_, _, err := buildProviders([]config.ProviderSpec{
			{
				Name: "gh", Realm: "ghes-corp", Type: "github-app",
				Config: &config.GitHubAppConfig{AppID: 1, PrivateKey: "no-scheme"},
			},
		}, false)
		assert.Error(t, err)
	})
}

func TestBuildStore(t *testing.T) {
	t.Parallel()
	s, err := buildStore(context.Background(), config.StoreConfig{Type: "memory"})
	require.NoError(t, err)
	assert.NotNil(t, s)

	_, err = buildStore(context.Background(), config.StoreConfig{Type: "mystery"})
	assert.Error(t, err)
}

func capDevSpec(discovery string, resources []string, actions []core.Action) config.ProviderSpec {
	return config.ProviderSpec{
		Name:  "gh-1",
		Realm: "gh",
		Type:  config.KindGitHubApp,
		Capability: config.CapabilityBlock{
			Discovery:  discovery,
			Resources:  resources,
			MaxActions: actions,
		},
		Config: &config.GitHubAppConfig{AppID: 1, PrivateKey: "raw:pem"},
	}
}

func TestBuildProviderDevStatic(t *testing.T) {
	t.Parallel()
	is := assert.New(t)
	must := require.New(t)

	p, d, err := buildProvider(capDevSpec("static", []string{"gh:acme/*"}, []core.Action{"contents:read"}), true)
	must.NoError(err)
	caps, err := p.Capabilities(context.Background())
	must.NoError(err)
	is.Equal([]string{"gh:acme/*"}, caps.Resources)
	is.Equal([]core.Action{"contents:read"}, caps.MaxActions)
	is.Equal("static", d.Mode)
	is.Equal("gh-1", d.Name)
	is.Equal(config.KindGitHubApp, d.Type)
}

func TestBuildProviderDevAPINoCeilingServesNothing(t *testing.T) {
	t.Parallel()
	is := assert.New(t)
	must := require.New(t)

	// api discovery with no declared ceiling: the dev stub has nothing to discover.
	p, d, err := buildProvider(capDevSpec("api", nil, nil), true)
	must.NoError(err)
	caps, err := p.Capabilities(context.Background())
	must.NoError(err)
	is.Empty(caps.Resources, "pure-api realm serves nothing under --dev")
	is.Equal("api", d.Mode)
}

func TestBuildRealmsRejectsDuplicates(t *testing.T) {
	t.Parallel()
	_, err := buildRealms([]config.RealmBlock{
		{Realm: "github", Type: "github-app"},
		{Realm: "github", Type: "github-app"},
	})
	assert.Error(t, err, "duplicate realm names must fail closed")
}

func TestBuildRealmsDefaultedName(t *testing.T) {
	t.Parallel()
	norm, _ := config.NormalizeRealms([]config.RealmBlock{{Type: "github-app"}})
	reg, err := buildRealms(norm)
	require.NoError(t, err)
	_, ok := reg.Get("github")
	assert.True(t, ok, "defaulted realm registers under 'github'")
}
