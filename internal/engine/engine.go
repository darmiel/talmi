package engine

import (
	"github.com/darmiel/talmi/internal/core"
	"github.com/darmiel/talmi/internal/realm"
)

// Engine holds an immutable snapshot of rules and evaluates authorization against them.
// Build a new Engine to change rules!
type Engine struct {
	rules  []core.Rule
	realms *realm.Registry
}

// New creates a new Engine with the given rules and realm semantics.
func New(rules []core.Rule, realms *realm.Registry) *Engine {
	return &Engine{
		rules:  rules,
		realms: realms,
	}
}
