package configvet

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/darmiel/talmi/internal/config"
	"github.com/darmiel/talmi/internal/core"
)

func TestCheckRealmDefaults(t *testing.T) {
	t.Parallel()

	t.Run("omitted realm on known type warns and xref still resolves", func(t *testing.T) {
		t.Parallel()
		in := baseline()
		in.Sourced.Realms = []config.RealmBlock{
			{
				Type: "github-app",
				Capability: config.CapabilityBlock{
					Resources: []string{"github:acme/*"}, MaxActions: []core.Action{"contents:read"},
				},
				Instances: []config.InstanceBlock{
					{Name: "gh-1", Config: map[string]any{"app_id": 1, "private_key": "raw:pem"}},
				},
			},
		}
		// a rule referencing the DEFAULTED realm ("github") must resolve, not raise xref
		in.Sourced.Rules = []core.Rule{
			{
				Name:  "r",
				Match: core.Match{Issuer: "ci", AllowEmptyCondition: true},
				Allow: []core.Allow{{Resources: []string{"github:acme/*"}, Actions: []core.Action{"contents:read"}}},
			},
		}

		r := Static(in)
		assert.NotNil(t, findByCode(r, "CFG-REALM-DEFAULT"), "defaulting should warn")
		assert.Nil(t, findByCode(r, "CFG-XREF-REALM"), "rule xref must resolve against the defaulted realm")
		assert.Nil(t, findByCode(r, "CFG-REALM-DUP"))
	})

	t.Run("duplicate defaulted names error", func(t *testing.T) {
		t.Parallel()
		in := baseline()
		in.Sourced.Realms = []config.RealmBlock{
			{
				Type: "github-app", Instances: []config.InstanceBlock{
					{Name: "a", Config: map[string]any{"app_id": 1, "private_key": "raw:pem"}},
				},
			},
			{
				Type: "github-app", Instances: []config.InstanceBlock{
					{Name: "b", Config: map[string]any{"app_id": 2, "private_key": "raw:pem"}},
				},
			},
		}
		in.Sourced.Rules = nil

		r := Static(in)
		assert.NotNil(t, findByCode(r, "CFG-REALM-DUP"), "two omitted github-app realms both default to 'github'")
	})
}
