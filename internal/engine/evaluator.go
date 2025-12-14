package engine

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/expr-lang/expr"

	"github.com/darmiel/talmi/internal/core"
)

// ruleResult is a simplified result of rule evaluation
type ruleResult struct {
	Matched    bool
	Conditions []core.ConditionResult
}

// Evaluate evaluates the principal against the rules and returns the first matching rule and its grant.
func (e *Engine) Evaluate(principal *core.Principal, requestedProvider string) (*core.Rule, error) {
	for _, rule := range e.rules {
		result := checkRule(rule, principal, requestedProvider)
		if result.Matched {
			return &rule, nil
		}
	}
	return nil, ErrNoRuleMatch
}

// checkRule evaluates a single rule against the principal and requested provider.
func checkRule(rule core.Rule, principal *core.Principal, requestedProvider string) ruleResult {
	result := ruleResult{
		Matched:    true, // fail on any mismatch
		Conditions: []core.ConditionResult{},
	}

	addResult := func(expression string, passed bool, reason string) {
		result.Conditions = append(result.Conditions, core.ConditionResult{
			Expression: expression,
			Matched:    passed,
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

	cr := evaluateCondition(rule.Match.Condition, principal.Attributes)
	if !cr.Matched {
		result.Matched = false
	}
	flattenConditionResult(&result.Conditions, cr, 0)

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

func flattenConditionResult(out *[]core.ConditionResult, cr core.ConditionResult, depth int) {
	indent := strings.Repeat("  ", depth)

	if cr.Expression != "" {
		*out = append(*out, core.ConditionResult{
			Expression: indent + cr.Expression,
			Matched:    cr.Matched,
			Reason:     cr.Reason,
		})
		return
	}

	if cr.Label != "" {
		*out = append(*out, core.ConditionResult{
			Expression: indent + "[" + cr.Label + "]",
			Matched:    cr.Matched,
		})
	}

	for _, child := range cr.Children {
		flattenConditionResult(out, child, depth+1)
	}
}

func evaluateCondition(cond core.Condition, attributes map[string]any) core.ConditionResult {
	// logic operators
	if len(cond.All) > 0 {
		res := core.ConditionResult{
			Matched: true,
			Label:   "AND",
		}
		for _, child := range cond.All {
			cr := evaluateCondition(child, attributes)
			res.Children = append(res.Children, cr)
			if !cr.Matched {
				res.Matched = false
			}
		}
		return res
	}

	if len(cond.Any) > 0 {
		res := core.ConditionResult{
			Matched: false,
			Label:   "OR",
		}
		for _, child := range cond.Any {
			cr := evaluateCondition(child, attributes)
			res.Children = append(res.Children, cr)
			if cr.Matched {
				res.Matched = true
			}
		}
		return res
	}

	if cond.Not != nil {
		cr := evaluateCondition(*cond.Not, attributes)
		return core.ConditionResult{
			Matched:  !cr.Matched,
			Label:    "NOT",
			Children: []core.ConditionResult{cr},
		}
	}

	// leaf condition
	if cond.Key != "" {
		val, exists := attributes[cond.Key]

		createCondition := func(passed bool, reason string) core.ConditionResult {
			return core.ConditionResult{
				Matched:    passed,
				Expression: fmt.Sprintf("%s %s %v", cond.Key, cond.Operator, cond.Value),
				Reason:     reason,
			}
		}

		if cond.Operator == core.OpExists {
			if !exists {
				return createCondition(false, fmt.Sprintf("attribute '%s' does not exist", cond.Key))
			}
			return createCondition(true, "")
		}

		if !exists {
			return createCondition(false, fmt.Sprintf("attribute '%s' missing", cond.Key))
		}

		switch cond.Operator {
		case core.OpEqual:
			if !deepEqual(val, cond.Value) {
				return createCondition(false, fmt.Sprintf("expected '%v' to equal '%v'", val, cond.Value))
			}
			return createCondition(true, "")

		case core.OpContains:
			// check if {val} contains {cond.Value}
			// e.g. "sub contains "@acme.com"
			if !contains(val, cond.Value) {
				return createCondition(false, fmt.Sprintf("value '%v' not in '%v'", val, cond.Value))
			}
			return createCondition(true, fmt.Sprintf("value '%v' contains '%v'", val, cond.Value))

		case core.OpIn:
			// check if {cond.Value} contains {val}
			// e.g. "region IN ['us-east-1', 'us-west-2']"
			if !contains(cond.Value, val) {
				return createCondition(false, fmt.Sprintf("value '%v' not in list '%v'", val, cond.Value))
			}
			return createCondition(true, fmt.Sprintf("value '%v' found in list '%v'", val, cond.Value))
		}

		return createCondition(false, fmt.Sprintf("unknown operator '%s' in condition", cond.Operator))
	}

	return core.ConditionResult{
		Matched: true,
		Label:   "(empty)",
	}
}

func deepEqual(a, b any) bool {
	return reflect.DeepEqual(a, b)
}

func contains(container, item any) bool {
	// handle string contains substring
	if str, ok := container.(string); ok {
		if subStr, ok := item.(string); ok {
			return strings.Contains(str, subStr)
		}
	}

	// handle slice/array contains
	v := reflect.ValueOf(container)
	if v.Kind() == reflect.Slice || v.Kind() == reflect.Array {
		for i := 0; i < v.Len(); i++ {
			if deepEqual(v.Index(i).Interface(), item) {
				return true
			}
		}
	}

	return false
}
