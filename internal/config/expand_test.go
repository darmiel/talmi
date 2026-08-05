package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/darmiel/talmi/internal/secret"
)

func TestExpandProviders(t *testing.T) {
	t.Parallel()
	is := assert.New(t)

	realms := []RealmBlock{
		{
			Realm:      "ghes-corp",
			Type:       "github-app",
			Capability: CapabilityBlock{Discovery: "api"},
			Instances: []InstanceBlock{
				{
					Name:   "gh-ro",
					Config: map[string]any{"app_id": 1, "private_key": "file:/ro.pem"},
				},
				{
					Name:       "gh-rw",
					Config:     map[string]any{"app_id": 2, "private_key": "file:/rw.pem"},
					Capability: CapabilityBlock{Discovery: "static", Resources: []string{"ghes-corp:acme/svc-*"}},
				},
			},
		},
	}

	specs, err := ExpandProviders(realms)
	require.NoError(t, err)
	require.Len(t, specs, 2)

	is.Equal("gh-ro", specs[0].Name)
	is.Equal("ghes-corp", specs[0].Realm)
	is.Equal("api", specs[0].Capability.Discovery) // inherited realm capability
	gh, ok := specs[0].Config.(*GitHubAppConfig)
	require.True(t, ok, "expected *GitHubAppConfig, got %T", specs[0].Config)
	is.Equal(int64(1), gh.AppID)
	is.Equal(secret.Ref("file:/ro.pem"), gh.PrivateKey)

	is.Equal("static", specs[1].Capability.Discovery) // instance override
	is.Equal([]string{"ghes-corp:acme/svc-*"}, specs[1].Capability.Resources)
}

func TestExpandProvidersErrors(t *testing.T) {
	t.Parallel()
	ghCfg := map[string]any{"app_id": 1, "private_key": "raw:pem"}

	tests := []struct {
		name   string
		realms []RealmBlock
	}{
		{"missing realm name", []RealmBlock{{Type: "github-app", Instances: []InstanceBlock{{Name: "a", Config: ghCfg}}}}},
		{"missing type", []RealmBlock{{Realm: "r", Instances: []InstanceBlock{{Name: "a", Config: ghCfg}}}}},
		{"instance without name", []RealmBlock{{Realm: "r", Type: "github-app", Instances: []InstanceBlock{{}}}}},
		{
			"duplicate instance name", []RealmBlock{
				{Realm: "r1", Type: "github-app", Instances: []InstanceBlock{{Name: "dup", Config: ghCfg}}},
				{Realm: "r2", Type: "github-app", Instances: []InstanceBlock{{Name: "dup", Config: ghCfg}}},
			},
		},
		{
			"invalid instance config", []RealmBlock{
				{Realm: "r", Type: "github-app", Instances: []InstanceBlock{{Name: "a", Config: map[string]any{"appid": 1, "private_key": "raw:k"}}}},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := ExpandProviders(tt.realms)
			assert.Error(t, err)
		})
	}
}
