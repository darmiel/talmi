package capability

import (
	"context"
	"fmt"

	"github.com/darmiel/talmi/internal/core"
	"github.com/darmiel/talmi/internal/realm"
)

func resolveMode(discovery string, supportsAPI bool) string {
	switch discovery {
	case "static":
		return "static"
	case "api":
		return "api"
	default:
		if supportsAPI {
			return "api"
		}
		return "static"
	}
}

func Mode(discovery string, supportsAPI bool) string {
	return resolveMode(discovery, supportsAPI)
}

func declaredEmpty(c core.Capability) bool {
	return len(c.Resources) == 0 && len(c.MaxActions) == 0
}

func Decorate(
	p core.ResourceProvider,
	sem realm.Semantics,
	mode string,
	declared core.Capability,
) core.ResourceProvider {
	return &modeProvider{
		ResourceProvider: p,
		sem:              sem,
		mode:             mode,
		declared:         declared,
	}
}

var _ core.ResourceProvider = (*modeProvider)(nil)

type modeProvider struct {
	core.ResourceProvider
	sem      realm.Semantics
	mode     string
	declared core.Capability
}

func (m *modeProvider) Capabilities(ctx context.Context) (core.Capability, error) {
	if m.mode == "static" {
		return core.Capability{
			Realm:      m.ResourceProvider.Realm(),
			Resources:  m.declared.Resources,
			MaxActions: m.declared.MaxActions,
		}, nil
	}

	discovered, err := m.ResourceProvider.Capabilities(ctx)
	if err != nil {
		return core.Capability{}, err
	}
	if declaredEmpty(m.declared) {
		// no further restrictions exist: just return the capabilities as discovered
		return discovered, nil
	}
	return intersect(m.sem, discovered, m.declared), nil
}

func (m *modeProvider) Invalidate() {
	if inv, ok := m.ResourceProvider.(interface{ Invalidate() }); ok {
		inv.Invalidate()
	}
}

func (m *modeProvider) Revoke(ctx context.Context, revocationID, tokenValue string) error {
	rev, ok := m.ResourceProvider.(core.TokenRevoker)
	if !ok {
		return fmt.Errorf("provider %q does not support revocation", m.ResourceProvider.Name())
	}
	return rev.Revoke(ctx, revocationID, tokenValue)
}

func (m *modeProvider) RequiresTokenForRevocation() bool {
	rev, ok := m.ResourceProvider.(core.TokenRevoker)
	return ok && rev.RequiresTokenForRevocation()
}

func intersect(sem realm.Semantics, discovered, declared core.Capability) core.Capability {
	declaredActions := make(map[core.Action]bool, len(declared.MaxActions))
	for _, a := range declared.MaxActions {
		declaredActions[a] = true
	}
	var actions []core.Action
	for _, a := range discovered.MaxActions {
		if declaredActions[a] {
			actions = append(actions, a)
		}
	}
	out := core.Capability{
		Realm:      discovered.Realm,
		MaxActions: actions,
	}
	if len(actions) == 0 {
		return out // no shared actions
	}
	allow := core.Allow{
		Resources: declared.Resources,
		Actions:   declared.MaxActions,
	}
	for _, r := range discovered.Resources {
		req := core.ResourceRequest{
			Resource: core.Resource(r),
			Actions:  actions,
		}
		if ok, _ := sem.Covers([]core.Allow{allow}, req); ok {
			out.Resources = append(out.Resources, r)
		}
	}
	return out
}
