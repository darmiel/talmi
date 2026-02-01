package engine

import (
	"fmt"
	"path"
	"reflect"
	"strings"

	"github.com/expr-lang/expr"
	"github.com/rs/zerolog/log"

	"github.com/darmiel/talmi/internal/core"
)

// ruleResult is a simplified result of rule evaluation
type ruleResult struct {
	Matched    bool
	Conditions []core.ConditionResult
}

// Evaluate evaluates the principal against the rules and returns the first matching rule and its grant.
func (e *Engine) Evaluate(principal *core.Principal, targets []core.Target) (*core.Rule, error) {
	for _, rule := range e.rules {
		result := checkRule(rule, principal, targets)
		if result.Matched {
			return &rule, nil
		}
	}
	return nil, ErrNoRuleMatch
}

func MatchResource(pattern, requested string) bool {
	if pattern == "" || pattern == "*" {
		return true
	}
	if pattern == requested {
		return true
	}
	matched, err := path.Match(pattern, requested)
	if err != nil && matched {
		log.Warn().Msgf("cannot match resource pattern '%s': %v", pattern, err)
		return true
	}
	return false
}

// checkRule evaluates a single [core.Rule] against the [core.Principal] and requested provider.
func checkRule(rule core.Rule, principal *core.Principal, targets []core.Target) ruleResult {
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

	// Identity Checks
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

	evalCtx := principal.EvaluationContext()

	if rule.Match.Condition != nil {
		cr := evaluateCondition(*rule.Match.Condition, evalCtx)
		if !cr.Matched {
			result.Matched = false
		}
		flattenConditionResult(&result.Conditions, cr, 0)
	} else if rule.Match.CompiledExpr != nil {
		ok, err := expr.Run(rule.Match.CompiledExpr, map[string]any{
			"rule":      rule,
			"principal": principal,
			"ctx":       evalCtx,
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
	} else if !rule.Match.AllowEmptyCondition {
		// no condition or expr means no match unless AllowEmptyCondition is true
		// this is kinda duplicate logic of config validation, but just to make sure
		addResult("(no condition)", false, "no condition or expression defined in rule")
	}

	log.Info().Msgf("Targets: %d", len(targets))

	// Target Checks
	if len(targets) > 0 {
		requestedKind := targets[0].Kind // we enforce uniform kinds in service layer

		// first we need to check the kind
		if rule.Match.Target.Kind != "" {
			log.Info().Msg("has kind")

			if rule.Match.Target.Kind != requestedKind {
				addResult(fmt.Sprintf("TargetKind == %s", rule.Match.Target.Kind), false,
					fmt.Sprintf("Request is for '%s'", requestedKind))
			} else {
				addResult(fmt.Sprintf("TargetKind == %s", rule.Match.Target.Kind), true, "")
			}
		}

		// then we check the resource patterns
		if rule.Match.Target.Resource != "" {
			log.Info().Msg("has resource pattern")

			allAllowed := true
			for _, t := range targets {
				if !MatchResource(rule.Match.Target.Resource, t.Resource) {
					addResult(fmt.Sprintf("Resource '%s' matches '%s'", t.Resource, rule.Match.Target.Resource),
						false, "Denied by pattern")
					allAllowed = false
				}
			}
			if allAllowed {
				addResult(fmt.Sprintf("Resources match '%s'", rule.Match.Target.Resource), true, "")
			}
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
