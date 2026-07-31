package engine

import (
	"sync"
	"sync/atomic"

	"github.com/darmiel/talmi/internal/core"
	"github.com/darmiel/talmi/internal/realm"
)

type PolicyManager struct {
	currentEngine atomic.Pointer[Engine]
	realms        *realm.Registry
	mu            sync.Mutex
}

func NewManager(initialRules []core.Rule, realms *realm.Registry) *PolicyManager {
	m := &PolicyManager{
		realms: realms,
	}
	m.currentEngine.Store(New(initialRules, realms))
	return m
}

func (m *PolicyManager) GetEngine() *Engine {
	return m.currentEngine.Load()
}

func (m *PolicyManager) Update(newRules []core.Rule) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.currentEngine.Store(New(newRules, m.realms))
	return nil
}
