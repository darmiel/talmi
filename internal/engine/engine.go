package engine

import (
	"fmt"

	"github.com/darmiel/talmi/internal/core"
)

var ErrNoRuleMatch = fmt.Errorf("no matching rule found for this principal and resource")

// Engine holds the loaded policies and evaluates them.
type Engine struct {
	rules []core.Rule
}

// New creates a new Engine with the given rules.
func New(rules []core.Rule) *Engine {
	return &Engine{
		rules: rules,
	}
}

// Trace evaluates the principal against all rules and returns a detailed trace of the evaluation.
func (e *Engine) Trace(principal *core.Principal, targets []core.Target) core.EvaluationTrace {
	trace := core.EvaluationTrace{
		Principal:     principal,
		RuleResults:   make([]core.RuleResult, 0, len(e.rules)),
		FinalDecision: false,
	}

	for _, rule := range e.rules {
		result := checkRule(rule, principal, targets)

		apiResult := core.RuleResult{
			RuleName:         rule.Name,
			Description:      rule.Description,
			Matched:          result.Matched,
			ConditionResults: result.Conditions,
		}
		trace.RuleResults = append(trace.RuleResults, apiResult)

		if result.Matched {
			if !trace.FinalDecision {
				trace.FinalDecision = true
				trace.GrantedRule = rule.Name
				// keep going to show other rules in the trace, but mark it as "winner"
			}
		}
	}

	return trace
}
