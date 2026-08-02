package runtime

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/darmiel/talmi/internal/config"
	"github.com/darmiel/talmi/internal/core"
	"github.com/darmiel/talmi/internal/service"
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
		cap, err := ps[0].Capabilities(context.Background())
		require.NoError(t, err)
		assert.Equal(t, []string{"ghes-corp:acme/*"}, cap.Resources)
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
	s, cleanup, err := buildStore(context.Background(), config.StoreConfig{Type: "memory"})
	require.NoError(t, err)
	assert.NotNil(t, s)
	assert.Nil(t, cleanup)

	_, _, err = buildStore(context.Background(), config.StoreConfig{Type: "mystery"})
	assert.Error(t, err)
}

// TestBuildDevEndToEnd wires the whole stack (dev stubs) and mints a lease.
func TestBuildDevEndToEnd(t *testing.T) {
	t.Parallel()
	is := assert.New(t)

	cfg := &config.Config{
		Signing: config.SigningConfig{Key: "raw:dev-key"},
		Store:   config.StoreConfig{Type: "memory"},
		Audit:   config.AuditConfig{Enabled: false},
	}
	sourced := &config.SourcedConfig{
		Issuers: []config.IssuerBlock{
			{
				Name:   "ci",
				Type:   "static",
				Config: map[string]any{"token_map": map[string]any{"tok": map[string]any{"sub": "user"}}},
			},
		},
		Realms: []config.RealmBlock{
			{
				Realm: "ghes-corp", Type: "github-app",
				Capability: config.CapabilityBlock{
					Resources:  []string{"ghes-corp:acme/*"},
					MaxActions: []core.Action{"contents:read"},
				},
				Instances: []config.InstanceBlock{{Name: "gh-ro"}},
			},
		},
		Rules: []core.Rule{
			{
				Name:  "ci-read",
				Match: core.Match{Issuer: "ci", AllowEmptyCondition: true},
				Allow: []core.Allow{{Resources: []string{"ghes-corp:acme/*"}, Actions: []core.Action{"contents:read"}}},
			},
		},
	}

	rt, err := Build(context.Background(), cfg, sourced, "rev-1", true /* dev */)
	require.NoError(t, err)
	defer rt.Close()

	resp, err := rt.Service.IssueLease(context.Background(), service.IssueRequest{
		Token:     "tok",
		Resources: []core.ResourceRequest{{Resource: "ghes-corp:acme/x", Actions: []core.Action{"contents:read"}}},
	})
	require.NoError(t, err)
	require.Len(t, resp.Artifacts, 1)
	is.NotEmpty(resp.Artifacts[0].Token)
	is.Equal("gh-ro", resp.Artifacts[0].Provider)
}
