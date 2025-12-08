package engine

import (
	"fmt"

	"github.com/expr-lang/expr"
	"github.com/rs/zerolog/log"

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

func (e *Engine) Evaluate(principal *core.Principal, requestedProvider string) (*core.Grant, error) {
	for _, rule := range e.rules {
		if matches(rule, principal, requestedProvider) {
			grant := rule.Grant
			return &grant, nil
		}
	}
	return nil, ErrNoRuleMatch
}

func matches(rule core.Rule, principal *core.Principal, requestedProvider string) bool {
	if rule.Match.Issuer != principal.Issuer {
		return false
	}
	for key, requiredValue := range rule.Match.Attributes {
		actualValue, ok := principal.Attributes[key]
		if !ok || actualValue != requiredValue {
			return false
		}
	}
	if requestedProvider != "" && rule.Grant.Provider != requestedProvider {
		return false
	}
	// TODO(future): check how we can improve matching different resource types
	if rule.Match.CompiledExpr != nil {
		ok, err := expr.Run(rule.Match.CompiledExpr, map[string]any{
			"rule":      rule,
			"principal": principal,
		})
		if err != nil {
			log.Warn().Err(err).Msgf("error evaluating rule expression for rule '%s'", rule.Name)
			return false
		}
		b, bOk := ok.(bool)
		if !bOk || !b {
			return false
		}
	}
	return true
}
