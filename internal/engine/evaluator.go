package engine

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/expr-lang/expr"

	"github.com/darmiel/talmi/internal/core"
)

// Authorize reports whether every requested resource + action is covered by the union of allow statements from all
// rules matching the principal. Any uncovered request denies the entire authorization.
func (e *Engine) Authorize(principal *core.Principal, requests []core.ResourceRequest) core.Decision {
	var matched []string
	var union []core.Allow
	for _, rule := range e.rules {
		if e.ruleMatches(rule, principal) {
			matched = append(matched, rule.Name)
			union = append(union, rule.Allow...)
		}
	}

	decision := core.Decision{Authorized: true, PolicyNames: matched}
	for _, request := range requests {
		rd := core.RequestDecision{Request: request}
		realmName, ok := request.Resource.Realm()
		if !ok {
			rd.Reason = fmt.Sprintf("resource %q has no realm prefix", request.Resource)
		} else {
			semantics, ok := e.realms.Get(realmName)
			if !ok {
				rd.Reason = fmt.Sprintf("unknown realm %q for resource %q", realmName, request.Resource)
			} else if covered, reason := semantics.Covers(union, request); covered {
				rd.Covered = true
			} else {
				rd.Reason = reason
			}
		}
		if !rd.Covered {
			decision.Authorized = false
		}
		decision.PerRequest = append(decision.PerRequest, rd)
	}

	return decision
}

func (e *Engine) ruleMatches(rule core.Rule, principal *core.Principal) bool {
	if rule.Match.Issuer != principal.Issuer {
		return false
	}
	switch {
	case rule.Match.Condition != nil:
		return evaluateCondition(*rule.Match.Condition, principal.EvaluationContext()).Matched
	case rule.Match.CompiledExpr != nil:
		out, err := expr.Run(rule.Match.CompiledExpr, map[string]any{
			"ctx":       principal.EvaluationContext(),
			"principal": principal,
		})
		if err != nil {
			return false
		}
		b, ok := out.(bool)
		return ok && b
	default:
		return rule.Match.AllowEmptyCondition
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
			if !valuesEqual(val, cond.Value) {
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

func valuesEqual(a, b any) bool {
	if af, ok := toFloat(a); ok {
		if bf, ok := toFloat(b); ok {
			return af == bf
		}
	}
	return reflect.DeepEqual(a, b)
}

func toFloat(v any) (float64, bool) {
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return float64(rv.Int()), true
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return float64(rv.Uint()), true
	case reflect.Float32, reflect.Float64:
		return rv.Float(), true
	default:
		return 0, false
	}
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
			if valuesEqual(v.Index(i).Interface(), item) {
				return true
			}
		}
	}

	return false
}
