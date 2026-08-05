package configvet

import (
	"context"

	"github.com/darmiel/talmi/internal/core"
)

type LiveInput struct {
	Static    StaticInput
	Providers []core.ResourceProvider
}

// Live runs the full static pass plus network-based checks.
func Live(ctx context.Context, input LiveInput) Report {
	r := Static(input.Static)

	realmResources := make(map[string]int)
	for _, p := range input.Providers {
		caps, err := p.Capabilities(ctx)
		if err != nil {
			r.errorf("CFG-CAPABILITY", "capabilities", "providers["+p.Name()+"]",
				"provider %q: fetching capabilities failed: %v", p.Name(), err)
			continue
		}
		realmResources[caps.Realm] += len(caps.Resources)
	}

	seen := make(map[string]struct{})
	for _, rule := range input.Static.Sourced.Rules {
		for _, allow := range rule.Allow {
			for _, pat := range allow.Resources {
				rn, ok := core.Resource(pat).Realm()
				if !ok {
					continue // already reported by Static pass
				}
				key := rule.Name + "|" + rn
				if _, d := seen[key]; d {
					continue // already reported for this rule and realm
				}
				seen[key] = struct{}{}
				if realmResources[rn] == 0 {
					r.errorf("CFG-COVERAGE", "capabilities", "rules["+rule.Name+"].allow",
						"rule %q targets realm %q, but no working provider serves it", rule.Name, rn)
				}
			}
		}
	}

	return r
}
