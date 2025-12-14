package engine

import (
	"fmt"

	"github.com/expr-lang/expr"

	"github.com/darmiel/talmi/internal/core"
)

// ruleResult is a simplified result of rule evaluation
type ruleResult struct {
	Matched    bool
	Conditions []core.ConditionResult
}

// Evaluate evaluates the principal against the rules and returns the first matching rule and its grant.
func (e *Engine) Evaluate(principal *core.Principal, requestedProvider string) (*core.Rule, *core.Grant, error) {
	for _, rule := range e.rules {
		result := checkRule(rule, principal, requestedProvider)
		if result.Matched {
			grant := rule.Grant
			return &rule, &grant, nil
		}
	}
	return nil, nil, ErrNoRuleMatch
}

// checkRule evaluates a single rule against the principal and requested provider.
func checkRule(rule core.Rule, principal *core.Principal, requestedProvider string) ruleResult {
	result := ruleResult{
		Matched: true, // fail on any mismatch
	}

	addResult := func(expression string, passed bool, reason string) {
		result.Conditions = append(result.Conditions, core.ConditionResult{
			Expression: expression,
			Passed:     passed,
			Reason:     reason,
		})
		if !passed {
			result.Matched = false
		}
	}

	issuerExpr := fmt.Sprintf("issuer %s '%s'", core.OpEqual, rule.Match.Issuer)
	if rule.Match.Issuer != principal.Issuer {
		addResult(
			issuerExpr,
			false,
			fmt.Sprintf("issuer mismatch: expected '%s', got '%s'", rule.Match.Issuer, principal.Issuer),
		)
	} else {
		addResult(issuerExpr, true, "")
	}

	// match the conditions
	for _, cond := range rule.Match.Conditions {
		passed, reason := evaluateCondition(cond, principal.Attributes)
		expression := fmt.Sprintf("%s %s %v", cond.Key, cond.Operator, cond.Value)
		addResult(expression, passed, reason)
	}

	if rule.Match.CompiledExpr != nil {
		ok, err := expr.Run(rule.Match.CompiledExpr, map[string]any{
			"rule":      rule,
			"principal": principal,
		})
		if err != nil {
			addResult(rule.Match.Expr, false, fmt.Sprintf("error evaluating expression: %v", err))
		} else {
			b, bOk := ok.(bool)
			if !bOk || !b {
				addResult(rule.Match.Expr, false, "expression evaluated to false")
			} else {
				addResult(rule.Match.Expr, true, "")
			}
		}
	}

	if requestedProvider != "" {
		providerExpr := fmt.Sprintf("provider %s '%s'", core.OpEqual, rule.Grant.Provider)
		if rule.Grant.Provider != requestedProvider {
			addResult(
				providerExpr,
				false,
				fmt.Sprintf("provider mismatch: requested '%s', got '%s'", requestedProvider, rule.Grant.Provider),
			)
		} else {
			addResult(providerExpr, true, "")
		}
	}

	return result
}
