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
			{Name: "gh", Realm: "ghes-corp", Type: "github-app", AppID: 1, PrivateKey: "raw:dummy-pem"},
			{
				Name:       "art",
				Realm:      "art",
				Type:       "artifactory",
				BaseURL:    "https://art",
				AdminToken: "raw:tok",
				Groups:     []string{"g"},
			},
		}
		ps, err := buildProviders(specs, false)
		require.NoError(t, err)
		require.Len(t, ps, 2)
		assert.Equal(t, "gh", ps[0].Name())
		assert.Equal(t, "art", ps[1].Name())
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
		ps, err := buildProviders(specs, true)
		require.NoError(t, err)
		require.Len(t, ps, 1)
		caps, err := ps[0].Capabilities(context.Background())
		require.NoError(t, err)
		assert.Equal(t, []string{"ghes-corp:acme/*"}, caps.Resources)
	})

	t.Run("unknown type", func(t *testing.T) {
		t.Parallel()
		_, err := buildProviders([]config.ProviderSpec{{Name: "x", Type: "weird"}}, false)
		assert.Error(t, err)
	})

	t.Run("bad secret ref", func(t *testing.T) {
		t.Parallel()
		_, err := buildProviders([]config.ProviderSpec{
			{
				Name:       "gh",
				Type:       "github-app",
				PrivateKey: "no-scheme",
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
