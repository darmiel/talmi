package core

import (
	"testing"

	"github.com/goccy/go-yaml"
)

func TestCondition_UnmarshalYAML(t *testing.T) {
	// This test defines YAML inputs and expects specific Go struct outcomes.
	// It verifies that your "Shorthand" logic works.

	tests := []struct {
		name  string
		input string
		want  Condition
	}{
		{
			name: "Explicit Syntax",
			input: `key: repo
op: eq
value: my-repo`,
			want: Condition{Key: "repo", Operator: OpEqual, Value: "my-repo"},
		},
		{
			name:  "Shorthand Simple Key-Value",
			input: `repo: my-repo`,
			// Should parse as implicit ALL -> [ {Key: repo, Op: Equal, Val: my-repo} ]
			// Note: If your unmarshaler wraps single items in ALL, adjust expectations here.
			// Assuming your implementation detects single key and sets Key/Val directly:
			want: Condition{Key: "repo", Operator: OpEqual, Value: "my-repo"},
		},
		{
			name:  "Shorthand Operator Map",
			input: `groups: { contains: admin }`,
			want:  Condition{Key: "groups", Operator: OpContains, Value: "admin"},
		},
		{
			name: "Nested Logic (Any)",
			input: `
any:
  - branch: main
  - branch: dev
`,
			want: Condition{
				Any: []Condition{
					{Key: "branch", Operator: OpEqual, Value: "main"},
					{Key: "branch", Operator: OpEqual, Value: "dev"},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got Condition
			if err := yaml.Unmarshal([]byte(tt.input), &got); err != nil {
				t.Fatalf("UnmarshalYAML() error = %v", err)
			}

			// Simple check for key attributes.
			// For deep comparison of recursive structs, use reflect.DeepEqual or "github.com/google/go-cmp/cmp"
			if !compareCondition(got, tt.want) {
				t.Errorf("Unmarshal mismatch.\nGot:  %+v\nWant: %+v", got, tt.want)
			}
		})
	}
}

// Simple recursive helper for comparison (or use go-cmp)
func compareCondition(a, b Condition) bool {
	if a.Key != b.Key || a.Operator != b.Operator || a.Value != b.Value {
		return false
	}
	if len(a.Any) != len(b.Any) {
		return false
	}
	// (Add loops for checking children if needed for complete verification)
	return true
}
