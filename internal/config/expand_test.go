package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExpandProviders(t *testing.T) {
	t.Parallel()
	is := assert.New(t)

	realms := []RealmBlock{
		{
			Realm:      "ghes-corp",
			Type:       "github-app",
			Server:     "https://ghes/api/v3",
			Capability: CapabilityBlock{Discovery: "api"},
			Instances: []InstanceBlock{
				{
					Name:       "gh-ro",
					AppID:      1,
					PrivateKey: "file:/ro.pem",
				},
				{
					Name:       "gh-rw",
					AppID:      2,
					PrivateKey: "file:/rw.pem",
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
	is.Equal("https://ghes/api/v3", specs[0].Server) // inherited
	is.Equal("api", specs[0].Capability.Discovery)   // inherited realm capability

	is.Equal("static", specs[1].Capability.Discovery) // instance override
	is.Equal([]string{"ghes-corp:acme/svc-*"}, specs[1].Capability.Resources)
}

func TestExpandProvidersErrors(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		realms []RealmBlock
	}{
		{"missing realm name", []RealmBlock{{Type: "github-app", Instances: []InstanceBlock{{Name: "a"}}}}},
		{"missing type", []RealmBlock{{Realm: "r", Instances: []InstanceBlock{{Name: "a"}}}}},
		{"instance without name", []RealmBlock{{Realm: "r", Type: "github-app", Instances: []InstanceBlock{{}}}}},
		{
			"duplicate instance name", []RealmBlock{
				{Realm: "r1", Type: "github-app", Instances: []InstanceBlock{{Name: "dup"}}},
				{Realm: "r2", Type: "github-app", Instances: []InstanceBlock{{Name: "dup"}}},
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
