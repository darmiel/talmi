package engine

import (
	"sync"
	"sync/atomic"

	"github.com/darmiel/talmi/internal/core"
)

type PolicyManager struct {
	currentEngine atomic.Pointer[Engine]
	mu            sync.Mutex
}

func NewManager(initialRules []core.Rule) *PolicyManager {
	m := &PolicyManager{}
	eng := New(initialRules)
	m.currentEngine.Store(eng)
	return m
}

func (m *PolicyManager) GetEngine() *Engine {
	return m.currentEngine.Load()
}

func (m *PolicyManager) Update(newRules []core.Rule) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	candidate := New(newRules)
	// TODO: validate here?

	m.currentEngine.Store(candidate)
	return nil
}
