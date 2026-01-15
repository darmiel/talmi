package validation

import (
	"fmt"

	"github.com/expr-lang/expr"

	"github.com/darmiel/talmi/internal/core"
)

func ValidateRules(rules []core.Rule, knownIssuers, knownProviders map[string]struct{}) ([]core.Rule, error) {
	seenNames := make(map[string]struct{})
	var validRules []core.Rule

	for i, rule := range rules {
		if rule.Name == "" {
			return nil, fmt.Errorf("rule #%d missing name", i)
		}
		if _, exists := seenNames[rule.Name]; exists {
			return nil, fmt.Errorf("rule name '%s' is not unique", rule.Name)
		}
		seenNames[rule.Name] = struct{}{}

		if rule.Match.Issuer == "" {
			return nil, fmt.Errorf("rule '%s' missing match.issuer", rule.Name)
		}
		if _, known := knownIssuers[rule.Match.Issuer]; !known {
			return nil, fmt.Errorf("rule '%s' references unknown issuer '%s'", rule.Name, rule.Match.Issuer)
		}

		if rule.Grant.Provider == "" {
			return nil, fmt.Errorf("rule '%s' missing grant.provider", rule.Name)
		}
		if _, known := knownProviders[rule.Grant.Provider]; !known {
			return nil, fmt.Errorf("rule '%s' references unknown provider '%s'", rule.Name, rule.Grant.Provider)
		}

		if rule.Match.Condition != nil && rule.Match.Expr != "" {
			return nil, fmt.Errorf("rule '%s' has both match.condition and match.expr set", rule.Name)
		}
		if rule.Match.Condition == nil && rule.Match.Expr == "" && !rule.Match.AllowEmptyCondition {
			return nil, fmt.Errorf("rule '%s' has neither match.condition nor match.expr set, and allow_empty_condition is false", rule.Name)
		}
		if rule.Match.Expr != "" {
			// compile and validate expression
			out, err := expr.Compile(rule.Match.Expr, expr.AsBool())
			if err != nil {
				return nil, fmt.Errorf("compiling expr for rule '%s': %w", rule.Name, err)
			}
			rule.Match.CompiledExpr = out
		}
		if rule.Match.Condition != nil {
			if err := rule.Match.Condition.Validate(); err != nil {
				return nil, fmt.Errorf("validating condition for rule '%s': %w", rule.Name, err)
			}
		}

		validRules = append(validRules, rule)
	}

	return validRules, nil
}
