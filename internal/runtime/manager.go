package runtime

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/darmiel/talmi/internal/config"
	"github.com/darmiel/talmi/internal/source"
)

// Manager holds the stable components and initial Runtime.
type Manager struct {
	current atomic.Pointer[Runtime]
	mu      sync.Mutex
	cfg     *config.Config
	source  source.Source
	dev     bool
	stable  stable
}

func NewManager(ctx context.Context, cfg *config.Config, src source.Source, dev bool) (*Manager, error) {
	st, err := buildStable(ctx, cfg)
	if err != nil {
		return nil, err
	}
	m := &Manager{
		cfg:    cfg,
		source: src,
		dev:    dev,
		stable: *st,
	}
	if err := m.reload(ctx, true); err != nil {
		_ = st.Close()
		return nil, err
	}
	return m, nil
}

// Current returns the active runtime.
func (m *Manager) Current() *Runtime {
	return m.current.Load()
}

// Reload fetches the source and (if the revision changed) atomically swaps a new runtime in place.
func (m *Manager) Reload(ctx context.Context) error {
	return m.reload(ctx, false)
}

func (m *Manager) reload(ctx context.Context, initial bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	sourced, revision, err := m.source.Load(ctx)
	if err != nil {
		return fmt.Errorf("loading sourced config: %w", err)
	}
	if !initial {
		if cur := m.current.Load(); cur != nil && cur.Revision == revision {
			return nil // unchanged, no need to reload
		}
	}

	rt, err := buildReloadable(ctx, sourced, revision, m.dev, m.stable)
	if err != nil {
		return fmt.Errorf("building reloadable runtime: %w", err)
	}
	m.current.Store(rt)
	return nil
}

// Close releases the stable components.
func (m *Manager) Close() error {
	return m.stable.Close()
}

func (m *Manager) InvalidateProviders() {
	rt := m.current.Load()
	if rt == nil {
		return
	}
	for _, p := range rt.Providers {
		if inv, ok := p.(interface{ Invalidate() }); ok {
			inv.Invalidate()
		}
	}
}
