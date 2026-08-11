package core

import (
	"testing"

	"github.com/goccy/go-yaml"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConditionValidate(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		cond    *Condition
		wantErr bool
	}{
		{"nil condition is valid (no restriction)", nil, false},
		{"valid leaf", &Condition{Key: "env", Operator: OpEqual, Value: "prod"}, false},
		{"valid exists leaf", &Condition{Key: "env", Operator: OpExists}, false},
		{"valid all", &Condition{All: []Condition{{Key: "a", Operator: OpEqual, Value: 1}}}, false},
		{"valid any", &Condition{Any: []Condition{{Key: "a", Operator: OpEqual, Value: 1}}}, false},
		{"valid not", &Condition{Not: &Condition{Key: "a", Operator: OpEqual, Value: 1}}, false},

		{"empty condition is invalid", &Condition{}, true},
		{"invalid operator on leaf", &Condition{Key: "env", Operator: "weird", Value: "x"}, true},
		{"multiple types set (leaf + all)", &Condition{Key: "a", Operator: OpEqual, All: []Condition{{Key: "b", Operator: OpEqual}}}, true},
		{"multiple types set (all + any)", &Condition{All: []Condition{{Key: "a", Operator: OpEqual}}, Any: []Condition{{Key: "b", Operator: OpEqual}}}, true},
		{"invalid nested child in all", &Condition{All: []Condition{{Key: "a", Operator: "nope"}}}, true},
		{"invalid nested child in any", &Condition{Any: []Condition{{Key: "a", Operator: "nope"}}}, true},
		{"invalid nested child in not", &Condition{Not: &Condition{Key: "a", Operator: "nope"}}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.cond.Validate()
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestConditionIsEmpty(t *testing.T) {
	t.Parallel()
	var nilCond *Condition
	assert.True(t, nilCond.IsEmpty(), "nil condition is empty")
	assert.True(t, (&Condition{}).IsEmpty(), "zero condition is empty")
	assert.False(t, (&Condition{Key: "a"}).IsEmpty(), "leaf is not empty")
	assert.False(t, (&Condition{All: []Condition{{Key: "a"}}}).IsEmpty(), "all is not empty")
	assert.False(t, (&Condition{Any: []Condition{{Key: "a"}}}).IsEmpty(), "any is not empty")
	assert.False(t, (&Condition{Not: &Condition{Key: "a"}}).IsEmpty(), "not is not empty")
}

func TestConditionUnmarshalEdgeCases(t *testing.T) {
	t.Parallel()

	t.Run("shorthand simple key:value defaults to equals", func(t *testing.T) {
		t.Parallel()
		var c Condition
		require.NoError(t, yaml.Unmarshal([]byte(`env: prod`), &c))
		assert.Equal(t, "env", c.Key)
		assert.Equal(t, OpEqual, c.Operator)
		assert.Equal(t, "prod", c.Value)
	})

	t.Run("shorthand operator map", func(t *testing.T) {
		t.Parallel()
		var c Condition
		require.NoError(t, yaml.Unmarshal([]byte(`teams: { contains: "org/admins" }`), &c))
		assert.Equal(t, "teams", c.Key)
		assert.Equal(t, OpContains, c.Operator)
		assert.Equal(t, "org/admins", c.Value)
	})

	t.Run("explicit long form with list value (operator collision escape hatch)", func(t *testing.T) {
		t.Parallel()
		var c Condition
		require.NoError(t, yaml.Unmarshal([]byte("key: region\noperator: in\nvalue: [us-east, eu-west]"), &c))
		assert.Equal(t, "region", c.Key)
		assert.Equal(t, OpIn, c.Operator)
		list, ok := c.Value.([]any)
		require.True(t, ok, "value should decode to a list, got %T", c.Value)
		assert.Len(t, list, 2)
	})

	t.Run("explicit form missing operator defaults to equals", func(t *testing.T) {
		t.Parallel()
		var c Condition
		require.NoError(t, yaml.Unmarshal([]byte("key: env\nvalue: prod"), &c))
		assert.Equal(t, "env", c.Key)
		assert.Equal(t, OpEqual, c.Operator)
	})

	t.Run("multiple keys become an implicit AND", func(t *testing.T) {
		t.Parallel()
		var c Condition
		require.NoError(t, yaml.Unmarshal([]byte("team: platform\nenv: prod"), &c))
		require.Len(t, c.All, 2, "two shorthand keys must fold into an AND")
		keys := map[string]bool{}
		for _, sub := range c.All {
			keys[sub.Key] = true
			assert.Equal(t, OpEqual, sub.Operator)
		}
		assert.True(t, keys["team"] && keys["env"])
	})

	t.Run("nested not with shorthand child", func(t *testing.T) {
		t.Parallel()
		var c Condition
		require.NoError(t, yaml.Unmarshal([]byte("not:\n  user: bob@corp.com"), &c))
		require.NotNil(t, c.Not)
		assert.Equal(t, "user", c.Not.Key)
		assert.Equal(t, OpEqual, c.Not.Operator)
		assert.Equal(t, "bob@corp.com", c.Not.Value)
	})

	t.Run("nested all + any tree", func(t *testing.T) {
		t.Parallel()
		var c Condition
		input := "all:\n  - any:\n      - branch: main\n      - branch: release\n  - env: prod"
		require.NoError(t, yaml.Unmarshal([]byte(input), &c))
		require.Len(t, c.All, 2)
		// first child is an ANY with two branches
		assert.Len(t, c.All[0].Any, 2)
	})

	t.Run("boolean and numeric shorthand values", func(t *testing.T) {
		t.Parallel()
		var b Condition
		require.NoError(t, yaml.Unmarshal([]byte(`verified: true`), &b))
		assert.Equal(t, "verified", b.Key)
		assert.Equal(t, true, b.Value)

		var n Condition
		require.NoError(t, yaml.Unmarshal([]byte(`tier: 3`), &n))
		assert.Equal(t, "tier", n.Key)
		assert.NotNil(t, n.Value)
	})

	t.Run("attribute literally named 'value' collides and parses empty (needs long form)", func(t *testing.T) {
		t.Parallel()
		// A claim key that collides with a struct field ("value"/"key"/"operator"/
		// "all"/"any"/"not") triggers the explicit-parse path and yields a
		// degenerate condition. It is caught by Validate() as empty -> fail-closed.
		var c Condition
		require.NoError(t, yaml.Unmarshal([]byte(`value: admin`), &c))
		assert.True(t, c.IsEmpty(), "a 'value:' shorthand is misparsed as empty")
		assert.Error(t, c.Validate(), "such a condition must be rejected by validation, not silently match")
	})

	t.Run("attribute named like an operator works via shorthand", func(t *testing.T) {
		t.Parallel()
		// "in" is an operator name but also a plausible attribute key. As a
		// top-level shorthand key it is NOT a struct field, so it parses fine.
		var c Condition
		require.NoError(t, yaml.Unmarshal([]byte(`in: { equals: "value-x" }`), &c))
		assert.Equal(t, "in", c.Key)
		assert.Equal(t, OpEqual, c.Operator)
		assert.Equal(t, "value-x", c.Value)
	})

	t.Run("non-map, non-scalar shorthand value", func(t *testing.T) {
		t.Parallel()
		// A list value in shorthand (no operator) defaults to equals against the list.
		var c Condition
		require.NoError(t, yaml.Unmarshal([]byte(`groups: [a, b]`), &c))
		assert.Equal(t, "groups", c.Key)
		assert.Equal(t, OpEqual, c.Operator)
	})

	t.Run("map value with no recognized operator defaults to equals-against-map", func(t *testing.T) {
		t.Parallel()
		// { groups: { notanop: x } } - "notanop" isn't a known operator, so the
		// whole map becomes the equality target. This effectively never matches a
		// scalar attribute; documented so the surprising shape is visible.
		var c Condition
		require.NoError(t, yaml.Unmarshal([]byte(`groups: { notanop: x }`), &c))
		assert.Equal(t, "groups", c.Key)
		assert.Equal(t, OpEqual, c.Operator)
		_, isMap := c.Value.(map[string]any)
		assert.True(t, isMap, "value should be the entire map, got %T", c.Value)
	})
}

func TestConditionUnmarshalErrors(t *testing.T) {
	t.Parallel()

	t.Run("a scalar (non-map) condition is rejected", func(t *testing.T) {
		t.Parallel()
		var c Condition
		err := yaml.Unmarshal([]byte(`just-a-string`), &c)
		assert.Error(t, err, "a bare scalar cannot be a condition")
	})

	t.Run("explicit key with a wrong-typed value is rejected", func(t *testing.T) {
		t.Parallel()
		// "key" is a struct field of type string; giving it a sequence must fail
		// the strict struct decode rather than silently producing garbage.
		var c Condition
		err := yaml.Unmarshal([]byte("key: [a, b]\nvalue: x"), &c)
		assert.Error(t, err)
	})
}

// TestEvaluationContextReservedKeys verifies the server-derived identity fields
// always win over attributes of the same name (anti-spoofing) and that
// attributes are copied, not aliased.
func TestEvaluationContextReservedKeys(t *testing.T) {
	t.Parallel()
	is := assert.New(t)

	p := &Principal{
		ID:     "real-subject",
		Issuer: "trusted-issuer",
		Attributes: map[string]any{
			"team":   "platform",
			"sub":    "spoofed",
			"iss":    "spoofed",
			"id":     "spoofed",
			"issuer": "spoofed",
		},
	}
	ctx := p.EvaluationContext()
	is.Equal("platform", ctx["team"], "normal attributes pass through")
	is.Equal("real-subject", ctx["sub"], "sub is forced to the verified id")
	is.Equal("real-subject", ctx["id"], "id is forced to the verified id")
	is.Equal("trusted-issuer", ctx["iss"], "iss is forced to the verified issuer")
	is.Equal("trusted-issuer", ctx["issuer"], "issuer is forced to the verified issuer")

	// mutating the returned context must not mutate the principal's attributes
	ctx["team"] = "mutated"
	is.Equal("platform", p.Attributes["team"], "EvaluationContext must copy, not alias")
}

func TestEvaluationContextNilAttributes(t *testing.T) {
	t.Parallel()
	is := assert.New(t)
	p := &Principal{ID: "a", Issuer: "b"}
	ctx := p.EvaluationContext()
	is.Len(ctx, 4)
	is.Equal("a", ctx["sub"])
	is.Equal("a", ctx["id"])
	is.Equal("b", ctx["iss"])
	is.Equal("b", ctx["issuer"])
}

func TestTokenArtifactRevocationIDRoundTrip(t *testing.T) {
	t.Parallel()
	var a TokenArtifact
	assert.Empty(t, a.RevocationID())
	a.SetRevocationID("token-id-123")
	assert.Equal(t, "token-id-123", a.RevocationID())
}
