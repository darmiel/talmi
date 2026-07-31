package engine

import (
	"testing"

	"github.com/expr-lang/expr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/darmiel/talmi/internal/core"
	"github.com/darmiel/talmi/internal/realm"
)

func newTestEngine(rules []core.Rule) *Engine {
	reg := realm.NewRegistry()
	reg.Register("ghes-corp", realm.GitHub{})
	return New(rules, reg)
}

func TestAuthorize(t *testing.T) {
	t.Parallel()

	rules := []core.Rule{
		{
			Name:  "read",
			Match: core.Match{Issuer: "cc", AllowEmptyCondition: true},
			Allow: []core.Allow{{Resources: []string{"ghes-corp:acme/*"}, Actions: []core.Action{"contents:read"}}},
		},
		{
			Name:  "write-svc",
			Match: core.Match{Issuer: "cc", AllowEmptyCondition: true},
			Allow: []core.Allow{
				{
					Resources: []string{"ghes-corp:acme/svc-*"},
					Actions:   []core.Action{"contents:write"},
				},
			},
		},
		{
			Name:  "other-issuer",
			Match: core.Match{Issuer: "someone-else", AllowEmptyCondition: true},
			Allow: []core.Allow{{Resources: []string{"ghes-corp:acme/*"}, Actions: []core.Action{"contents:write"}}},
		},
	}
	e := newTestEngine(rules)
	principal := &core.Principal{Issuer: "cc"}

	t.Run("covered by union of two rules", func(t *testing.T) {
		t.Parallel()
		is := assert.New(t)
		dec := e.Authorize(principal, []core.ResourceRequest{
			{Resource: "ghes-corp:acme/lib", Actions: []core.Action{"contents:read"}},
			{Resource: "ghes-corp:acme/svc-a", Actions: []core.Action{"contents:write"}},
		})
		is.True(dec.Authorized)
		is.ElementsMatch([]string{"read", "write-svc"}, dec.PolicyNames)
	})

	t.Run("uncovered action denies whole decision", func(t *testing.T) {
		t.Parallel()
		is := assert.New(t)
		dec := e.Authorize(principal, []core.ResourceRequest{
			{Resource: "ghes-corp:acme/lib", Actions: []core.Action{"contents:write"}}, // lib is not svc-*
		})
		is.False(dec.Authorized)
		is.False(dec.PerRequest[0].Covered)
		is.NotEmpty(dec.PerRequest[0].Reason)
	})

	t.Run("non-matching issuer contributes nothing", func(t *testing.T) {
		t.Parallel()
		is := assert.New(t)
		dec := e.Authorize(&core.Principal{Issuer: "cc"}, []core.ResourceRequest{
			{Resource: "ghes-corp:acme/lib", Actions: []core.Action{"contents:write"}},
		})
		is.False(dec.Authorized) // only "other-issuer" grants write on lib, and it didn't match
	})

	t.Run("unknown realm is reported", func(t *testing.T) {
		t.Parallel()
		is := assert.New(t)
		dec := e.Authorize(principal, []core.ResourceRequest{
			{Resource: "mystery:x", Actions: []core.Action{"read"}},
		})
		is.False(dec.Authorized)
		is.Contains(dec.PerRequest[0].Reason, "unknown realm")
	})
}

func TestEvaluateCondition(t *testing.T) {
	tests := []struct {
		name       string
		condition  core.Condition
		attributes map[string]any
		want       bool
	}{
		// --- Basic Operators ---
		{
			name:       "OpEqual - Match String",
			condition:  core.Condition{Key: "env", Operator: core.OpEqual, Value: "prod"},
			attributes: map[string]any{"env": "prod"},
			want:       true,
		},
		{
			name:       "OpEqual - Mismatch String",
			condition:  core.Condition{Key: "env", Operator: core.OpEqual, Value: "prod"},
			attributes: map[string]any{"env": "dev"},
			want:       false,
		},
		{
			name:       "OpExists - True",
			condition:  core.Condition{Key: "secret", Operator: core.OpExists},
			attributes: map[string]any{"secret": "hidden"},
			want:       true,
		},
		{
			name:       "OpExists - False",
			condition:  core.Condition{Key: "missing", Operator: core.OpExists},
			attributes: map[string]any{"other": "val"},
			want:       false,
		},

		// --- List Logic (Contains / In) ---
		{
			name:       "OpContains - List contains Item",
			condition:  core.Condition{Key: "groups", Operator: core.OpContains, Value: "admin"},
			attributes: map[string]any{"groups": []string{"user", "admin", "guest"}},
			want:       true,
		},
		{
			name:       "OpContains - String contains Substring",
			condition:  core.Condition{Key: "email", Operator: core.OpContains, Value: "@company.com"},
			attributes: map[string]any{"email": "employee@company.com"},
			want:       true,
		},
		{
			name:       "OpIn - Value in Allowed List",
			condition:  core.Condition{Key: "region", Operator: core.OpIn, Value: []string{"us-east", "eu-west"}},
			attributes: map[string]any{"region": "eu-west"},
			want:       true,
		},
		{
			name:       "OpIn - Value NOT in List",
			condition:  core.Condition{Key: "region", Operator: core.OpIn, Value: []string{"us-east"}},
			attributes: map[string]any{"region": "ap-south"},
			want:       false,
		},

		// --- Logic Gates (AND/OR/NOT) ---
		{
			name: "Logic - AND (All Pass)",
			condition: core.Condition{
				All: []core.Condition{
					{Key: "a", Operator: core.OpEqual, Value: 1},
					{Key: "b", Operator: core.OpEqual, Value: 2},
				},
			},
			attributes: map[string]any{"a": 1, "b": 2},
			want:       true,
		},
		{
			name: "Logic - AND (One Fail)",
			condition: core.Condition{
				All: []core.Condition{
					{Key: "a", Operator: core.OpEqual, Value: 1},
					{Key: "b", Operator: core.OpEqual, Value: 999},
				},
			},
			attributes: map[string]any{"a": 1, "b": 2},
			want:       false,
		},
		{
			name: "Logic - OR (One Pass)",
			condition: core.Condition{
				Any: []core.Condition{
					{Key: "a", Operator: core.OpEqual, Value: 999}, // Fail
					{Key: "b", Operator: core.OpEqual, Value: 2},   // Pass
				},
			},
			attributes: map[string]any{"a": 1, "b": 2},
			want:       true,
		},
		{
			name: "Logic - NOT (Invert)",
			condition: core.Condition{
				Not: &core.Condition{Key: "role", Operator: core.OpEqual, Value: "admin"},
			},
			attributes: map[string]any{"role": "user"}, // is NOT admin -> True
			want:       true,
		},

		// --- Nested Complexity ---
		{
			name: "Complex - (A=1 OR B=2) AND C=3",
			condition: core.Condition{
				All: []core.Condition{
					{
						Any: []core.Condition{
							{Key: "a", Operator: core.OpEqual, Value: 1},
							{Key: "b", Operator: core.OpEqual, Value: 2},
						},
					},
					{Key: "c", Operator: core.OpEqual, Value: 3},
				},
			},
			attributes: map[string]any{"a": 99, "b": 2, "c": 3}, // b=2 passes OR, c=3 passes AND
			want:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := evaluateCondition(tt.condition, tt.attributes)
			if got.Matched != tt.want {
				t.Errorf("evaluateCondition() matched = %v, want %v. Reason: %s", got.Matched, tt.want, got.Reason)
			}
		})
	}
}

func TestAuthorizeEdgeCases(t *testing.T) {
	t.Parallel()
	e := newTestEngine([]core.Rule{
		{
			Name:  "read",
			Match: core.Match{Issuer: "cc", AllowEmptyCondition: true},
			Allow: []core.Allow{{Resources: []string{"ghes-corp:acme/*"}, Actions: []core.Action{"contents:read"}}},
		},
	})
	p := &core.Principal{Issuer: "cc"}

	t.Run("empty requests is vacuously authorized", func(t *testing.T) {
		t.Parallel()
		is := assert.New(t)
		dec := e.Authorize(p, nil)
		is.True(dec.Authorized)
		is.Empty(dec.PerRequest)
	})

	t.Run("resource without realm prefix is reported", func(t *testing.T) {
		t.Parallel()
		is := assert.New(t)
		dec := e.Authorize(p, []core.ResourceRequest{{Resource: "no-colon", Actions: []core.Action{"contents:read"}}})
		is.False(dec.Authorized)
		is.Contains(dec.PerRequest[0].Reason, "no realm prefix")
	})

	t.Run("mixed covered and uncovered fails whole decision", func(t *testing.T) {
		t.Parallel()
		is := assert.New(t)
		dec := e.Authorize(p, []core.ResourceRequest{
			{Resource: "ghes-corp:acme/a", Actions: []core.Action{"contents:read"}},  // covered
			{Resource: "ghes-corp:acme/b", Actions: []core.Action{"contents:write"}}, // not covered
		})
		is.False(dec.Authorized)
		is.True(dec.PerRequest[0].Covered)
		is.False(dec.PerRequest[1].Covered)
	})
}

func TestRuleMatches(t *testing.T) {
	t.Parallel()
	reg := realm.NewRegistry()
	e := New(nil, reg)

	t.Run("issuer mismatch", func(t *testing.T) {
		t.Parallel()
		r := core.Rule{Match: core.Match{Issuer: "a", AllowEmptyCondition: true}}
		assert.False(t, e.ruleMatches(r, &core.Principal{Issuer: "b"}))
	})
	t.Run("allow-empty matches when no condition/expr", func(t *testing.T) {
		t.Parallel()
		r := core.Rule{Match: core.Match{Issuer: "a", AllowEmptyCondition: true}}
		assert.True(t, e.ruleMatches(r, &core.Principal{Issuer: "a"}))
	})
	t.Run("no condition and allow-empty false does not match", func(t *testing.T) {
		t.Parallel()
		r := core.Rule{Match: core.Match{Issuer: "a"}}
		assert.False(t, e.ruleMatches(r, &core.Principal{Issuer: "a"}))
	})
	t.Run("condition match / no-match", func(t *testing.T) {
		t.Parallel()
		r := core.Rule{
			Match: core.Match{
				Issuer:    "a",
				Condition: &core.Condition{Key: "env", Operator: core.OpEqual, Value: "prod"},
			},
		}
		assert.True(t, e.ruleMatches(r, &core.Principal{Issuer: "a", Attributes: map[string]any{"env": "prod"}}))
		assert.False(t, e.ruleMatches(r, &core.Principal{Issuer: "a", Attributes: map[string]any{"env": "dev"}}))
	})
	t.Run("expr true / false", func(t *testing.T) {
		t.Parallel()
		prog, err := expr.Compile(`ctx.env == "prod"`, expr.AsBool())
		require.NoError(t, err)
		r := core.Rule{Match: core.Match{Issuer: "a", CompiledExpr: prog}}
		assert.True(t, e.ruleMatches(r, &core.Principal{Issuer: "a", Attributes: map[string]any{"env": "prod"}}))
		assert.False(t, e.ruleMatches(r, &core.Principal{Issuer: "a", Attributes: map[string]any{"env": "dev"}}))
	})
	t.Run("expr non-bool result is treated as no-match", func(t *testing.T) {
		t.Parallel()
		prog, err := expr.Compile(`42`) // no AsBool -> returns int
		require.NoError(t, err)
		r := core.Rule{Match: core.Match{Issuer: "a", CompiledExpr: prog}}
		assert.False(t, e.ruleMatches(r, &core.Principal{Issuer: "a"}))
	})
	t.Run("expr runtime error is treated as no-match", func(t *testing.T) {
		t.Parallel()
		prog, err := expr.Compile(`1 / ctx.zero`) // integer divide by zero at run time
		require.NoError(t, err)
		r := core.Rule{Match: core.Match{Issuer: "a", CompiledExpr: prog}}
		assert.False(t, e.ruleMatches(r, &core.Principal{Issuer: "a", Attributes: map[string]any{"zero": 0}}))
	})
}

func TestContains(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name            string
		container, item any
		want            bool
	}{
		{"string substring", "employee@acme.com", "@acme.com", true},
		{"string missing substring", "x@other.com", "@acme.com", false},
		{"slice contains", []string{"a", "b"}, "b", true},
		{"slice missing", []string{"a", "b"}, "c", false},
		{"slice of any (json-style)", []any{"a", "b"}, "b", true},
		{"numeric cross-type in slice", []any{float64(1), float64(2)}, 2, true}, // int item vs float64 elems
		{"non-string item in string container", "hello", 5, false},
		{"non-container returns false", 42, 42, false},
		{"empty container", []string{}, "a", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, contains(tt.container, tt.item))
		})
	}
}

func TestValuesEqual(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		a, b any
		want bool
	}{
		{"int equals int", 2, 2, true},
		{"float64 equals int (jwt vs yaml)", float64(2), 2, true},
		{"int equals uint", 2, uint(2), true},
		{"numeric mismatch", 2, 3, false},
		{"string equals", "x", "x", true},
		{"string vs number", "2", 2, false},
		{"bool equals", true, true, true},
		{"nil vs value", nil, 1, false},
		{"nil vs nil", nil, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, valuesEqual(tt.a, tt.b))
		})
	}
}

func TestEvaluateConditionRemainingBranches(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		condition  core.Condition
		attributes map[string]any
		want       bool
	}{
		{
			"unknown operator fails",
			core.Condition{Key: "x", Operator: "weird", Value: "y"},
			map[string]any{"x": "y"},
			false,
		},
		{
			"missing attribute for equals fails",
			core.Condition{Key: "x", Operator: core.OpEqual, Value: "y"},
			map[string]any{},
			false,
		},
		{
			"missing attribute for contains fails",
			core.Condition{Key: "x", Operator: core.OpContains, Value: "y"},
			map[string]any{},
			false,
		},
		{
			"NOT inverts a match",
			core.Condition{Not: &core.Condition{Key: "r", Operator: core.OpEqual, Value: "admin"}},
			map[string]any{"r": "admin"},
			false,
		},
		{"empty condition matches all (guarded by validation)", core.Condition{}, map[string]any{}, true},
		{
			"OpIn with non-list value fails",
			core.Condition{Key: "r", Operator: core.OpIn, Value: "not-a-list"},
			map[string]any{"r": "x"},
			false,
		},
		{
			"float claim equals int policy value",
			core.Condition{Key: "tier", Operator: core.OpEqual, Value: 2},
			map[string]any{"tier": float64(2)},
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, evaluateCondition(tt.condition, tt.attributes).Matched)
		})
	}
}
