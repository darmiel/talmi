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

func (e *Engine) Evaluate(principal *core.Principal, requestedResource core.Resource) (*core.Grant, error) {
	for _, rule := range e.rules {
		if matches(rule, principal, requestedResource) {
			grant := rule.Grant
			return &grant, nil
		}
	}
	return nil, ErrNoRuleMatch
}

func matches(rule core.Rule, principal *core.Principal, requestedResource core.Resource) bool {
	if rule.Match.Issuer != principal.Issuer {
		return false
	}
	for key, requiredValue := range rule.Match.Attributes {
		actualValue, ok := principal.Attributes[key]
		if !ok || actualValue != requiredValue {
			return false
		}
	}
	if rule.Grant.Resource.Type != requestedResource.Type {
		return false
	}
	// we support wildcards "*" in the rule to match any requested resource ID
	if rule.Grant.Resource.ID != "*" && rule.Grant.Resource.ID != requestedResource.ID {
		return false
	}
	return true
}
