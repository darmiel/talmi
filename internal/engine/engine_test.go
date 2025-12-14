package engine

import (
	"testing"

	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/vm"

	"github.com/darmiel/talmi/internal/core"
)

func TestEngine_Evaluate(t *testing.T) {
	// Helper to compile expr safely
	compile := func(code string) *vm.Program {
		p, err := expr.Compile(code, expr.Env(map[string]any{
			"rule":      core.Rule{},
			"principal": &core.Principal{},
		}))
		if err != nil {
			panic(err)
		}
		return p
	}

	rules := []core.Rule{
		{
			Name: "rule-admin",
			Match: core.Match{
				Issuer: "github",
				Condition: &core.Condition{
					Key: "role", Operator: core.OpEqual, Value: "admin",
				},
			},
			Grant: core.Grant{Provider: "aws-prod"},
		},
		{
			Name: "rule-dev",
			Match: core.Match{
				Issuer: "github",
				Condition: &core.Condition{
					Key: "role", Operator: core.OpEqual, Value: "dev",
				},
			},
			Grant: core.Grant{Provider: "aws-dev"},
		},
		{
			Name: "rule-expr",
			Match: core.Match{
				Issuer:       "github",
				Expr:         `principal.Attributes["age"] > 18`,
				CompiledExpr: compile(`principal.Attributes["age"] > 18`),
			},
			Grant: core.Grant{Provider: "beer-store"},
		},
	}

	eng := New(rules)

	tests := []struct {
		name        string
		principal   *core.Principal
		reqProvider string
		wantErr     bool
		wantRule    string
	}{
		{
			name: "Match Admin Rule",
			principal: &core.Principal{
				Issuer:     "github",
				Attributes: map[string]any{"role": "admin"},
			},
			wantRule: "rule-admin",
		},
		{
			name: "Match Dev Rule",
			principal: &core.Principal{
				Issuer:     "github",
				Attributes: map[string]any{"role": "dev"},
			},
			wantRule: "rule-dev",
		},
		{
			name: "No Match - Wrong Issuer",
			principal: &core.Principal{
				Issuer:     "gitlab",
				Attributes: map[string]any{"role": "admin"},
			},
			wantErr: true,
		},
		{
			name: "No Match - Wrong Attribute",
			principal: &core.Principal{
				Issuer:     "github",
				Attributes: map[string]any{"role": "intern"},
			},
			wantErr: true,
		},
		{
			name: "Provider Mismatch",
			principal: &core.Principal{
				Issuer:     "github",
				Attributes: map[string]any{"role": "admin"},
			},
			reqProvider: "aws-dev", // Rule grants aws-prod
			wantErr:     true,      // Should fail because I requested something I don't have access to
		},
		{
			name: "Expression Match",
			principal: &core.Principal{
				Issuer:     "github",
				Attributes: map[string]any{"age": 21},
			},
			wantRule: "rule-expr",
		},
		{
			name: "Expression Fail",
			principal: &core.Principal{
				Issuer:     "github",
				Attributes: map[string]any{"age": 16},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotRule, err := eng.Evaluate(tt.principal, tt.reqProvider)

			if tt.wantErr {
				if err == nil {
					t.Errorf("Evaluate() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("Evaluate() unexpected error: %v", err)
			}

			if gotRule.Name != tt.wantRule {
				t.Errorf("Evaluate() rule = %v, want %v", gotRule.Name, tt.wantRule)
			}
		})
	}
}
