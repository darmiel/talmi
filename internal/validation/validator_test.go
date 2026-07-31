package validation

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/darmiel/talmi/internal/core"
	"github.com/darmiel/talmi/internal/realm"
)

func testRealms() *realm.Registry {
	reg := realm.NewRegistry()
	reg.Register("ghes-corp", realm.GitHub{})
	return reg
}

func validRule() core.Rule {
	return core.Rule{
		Name:  "r1",
		Match: core.Match{Issuer: "cc", AllowEmptyCondition: true},
		Allow: []core.Allow{{Resources: []string{"ghes-corp:acme/*"}, Actions: []core.Action{"contents:read"}}},
	}
}

func TestValidateRules(t *testing.T) {
	t.Parallel()
	issuers := map[string]struct{}{"cc": {}}

	t.Run("valid rule passes", func(t *testing.T) {
		t.Parallel()
		out, err := ValidateRules([]core.Rule{validRule()}, issuers, testRealms())
		require.NoError(t, err)
		assert.Len(t, out, 1)
	})

	tests := []struct {
		name   string
		mutate func(r *core.Rule)
	}{
		{"missing name", func(r *core.Rule) { r.Name = "" }},
		{"unknown issuer", func(r *core.Rule) { r.Match.Issuer = "nope" }},
		{"no allow blocks", func(r *core.Rule) { r.Allow = nil }},
		{"allow without resources", func(r *core.Rule) { r.Allow[0].Resources = nil }},
		{"allow without actions", func(r *core.Rule) { r.Allow[0].Actions = nil }},
		{"pattern without realm", func(r *core.Rule) { r.Allow[0].Resources = []string{"no-colon"} }},
		{"unknown realm", func(r *core.Rule) { r.Allow[0].Resources = []string{"mystery:x/*"} }},
		{
			"both condition and expr", func(r *core.Rule) {
				r.Match.Expr = "true"
				r.Match.Condition = &core.Condition{Key: "x", Operator: core.OpEqual, Value: "y"}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := validRule()
			tt.mutate(&r)
			_, err := ValidateRules([]core.Rule{r}, issuers, testRealms())
			assert.Error(t, err)
		})
	}

	t.Run("duplicate names rejected", func(t *testing.T) {
		t.Parallel()
		_, err := ValidateRules([]core.Rule{validRule(), validRule()}, issuers, testRealms())
		assert.Error(t, err)
	})
}
