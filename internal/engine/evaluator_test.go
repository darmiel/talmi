package engine

import (
	"testing"

	"github.com/darmiel/talmi/internal/core"
)

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
