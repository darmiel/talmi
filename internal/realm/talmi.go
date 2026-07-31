package realm

import (
	"fmt"
	"slices"

	"github.com/darmiel/talmi/internal/core"
)

const KindTalmi = "talmi"

var _ Semantics = (*Talmi)(nil)

// Talmi implements Semantics for Talmi permissions.
type Talmi struct{}

func (Talmi) Kind() string {
	return KindTalmi
}

func (Talmi) Covers(allows []core.Allow, req core.ResourceRequest) (bool, string) {
	for _, act := range req.Actions {
		if !talmiActionCovered(allows, req.Resource, act) {
			return false, fmt.Sprintf("no allow grants %q on %q", act, req.Resource)
		}
	}
	return true, ""
}

func talmiActionCovered(allows []core.Allow, res core.Resource, want core.Action) bool {
	for _, allow := range allows {
		if matchAnyPattern(allow.Resources, res) && slices.Contains(allow.Actions, want) {
			return true
		}
	}
	return false
}

func (Talmi) CompareLevel(a, b core.Action) (int, error) {
	if a == b {
		return 0, nil
	}
	return 0, fmt.Errorf("talmi actions %q and %q are not ordered", a, b)
}

func (Talmi) ValidateResourcePattern(pattern string) error {
	r := core.Resource(pattern)
	if _, ok := r.Realm(); !ok {
		return fmt.Errorf("pattern %q is missing realm prefix", pattern)
	}
	if r.Body() == "" {
		return fmt.Errorf("pattern %q is missing body", pattern)
	}
	if err := validGlob(pattern); err != nil {
		return fmt.Errorf("pattern %q is not a valid glob: %v", pattern, err)
	}
	return nil
}
