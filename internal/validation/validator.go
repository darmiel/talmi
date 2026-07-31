package validation

import (
	"fmt"

	"github.com/expr-lang/expr"

	"github.com/darmiel/talmi/internal/core"
	"github.com/darmiel/talmi/internal/realm"
)

// ValidateRules validates and normalizes rules against the known issuers and realm semantics.
// It compiles any match expressions and validates conditions and allow patterns.
func ValidateRules(rules []core.Rule, knownIssuers map[string]struct{}, realms *realm.Registry) ([]core.Rule, error) {
	seen := make(map[string]struct{}, len(rules))
	valid := make([]core.Rule, 0, len(rules))

	for i, rule := range rules {
		if rule.Name == "" {
			return nil, fmt.Errorf("rule #%d missing name", i)
		}
		if _, ok := seen[rule.Name]; ok {
			return nil, fmt.Errorf("rule name %q is not unique", rule.Name)
		}
		seen[rule.Name] = struct{}{}

		if rule.Match.Issuer == "" {
			return nil, fmt.Errorf("rule %q: missing match.issuer", rule.Name)
		}
		if _, ok := knownIssuers[rule.Match.Issuer]; !ok {
			return nil, fmt.Errorf("rule %q: unknown issuer %q referenced", rule.Name, rule.Match.Issuer)
		}

		if len(rule.Allow) == 0 {
			return nil, fmt.Errorf("rule %q: missing allow statements", rule.Name)
		}
		if err := validateAllows(rule, realms); err != nil {
			return nil, err
		}
		if err := validateMatch(&rule); err != nil {
			return nil, err
		}

		valid = append(valid, rule)
	}

	return valid, nil
}

func validateAllows(rule core.Rule, realms *realm.Registry) error {
	for _, allow := range rule.Allow {
		if len(allow.Resources) == 0 {
			return fmt.Errorf("rule %q: allow statement has no resources", rule.Name)
		}
		if len(allow.Actions) == 0 {
			return fmt.Errorf("rule %q: allow statement has no actions", rule.Name)
		}
		for _, pattern := range allow.Resources {
			realmName, ok := core.Resource(pattern).Realm()
			if !ok {
				return fmt.Errorf("rule %q: pattern %q missing realm prefix", rule.Name, pattern)
			}
			semantics, ok := realms.Get(realmName)
			if !ok {
				return fmt.Errorf("rule %q: pattern %q references unknown realm %q",
					rule.Name, pattern, realmName)
			}
			if err := semantics.ValidateResourcePattern(pattern); err != nil {
				return fmt.Errorf("rule %q: pattern %q: %w", rule.Name, pattern, err)
			}
		}
	}
	return nil
}

func validateMatch(rule *core.Rule) error {
	m := &rule.Match
	switch {
	case m.Condition != nil && m.Expr != "":
		return fmt.Errorf("rule %q: both match.condition and match.expr are set", rule.Name)
	case m.Condition == nil && m.Expr == "" && !m.AllowEmptyCondition:
		return fmt.Errorf("rule %q: neither match.condition nor match.expr is set, and allow_empty is false",
			rule.Name)
	}

	// compile expression if present
	if m.Expr != "" {
		compiled, err := expr.Compile(m.Expr, expr.AsBool())
		if err != nil {
			return fmt.Errorf("rule %q: compiling match.expr: %w", rule.Name, err)
		}
		m.CompiledExpr = compiled
	}

	if m.Condition != nil {
		if err := m.Condition.Validate(); err != nil {
			return fmt.Errorf("rule %q: validating match.condition: %w", rule.Name, err)
		}
	}

	return nil
}
