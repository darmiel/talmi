package realm

import (
	"fmt"
	"strings"

	"github.com/darmiel/talmi/internal/core"
)

const KindArtifactory = "artifactory"

var _ Semantics = (*Artifactory)(nil)

// Artifactory implements Semantics for Artifactory permissions.
type Artifactory struct{}

func (Artifactory) Kind() string {
	return KindArtifactory
}

type afLevel int

const (
	afNone afLevel = iota
	afRead
	afAnnotate
	afWrite
)

func parseArtifactoryLevel(s string) (afLevel, bool) {
	switch strings.ToLower(s) {
	case "read":
		return afRead, true
	case "annotate":
		return afAnnotate, true
	case "write", "readwrite":
		return afWrite, true
	default:
		return afNone, false
	}
}

func (Artifactory) Covers(allows []core.Allow, req core.ResourceRequest) (bool, string) {
	for _, act := range req.Actions {
		if !artifactoryActionCovered(allows, req.Resource, act) {
			return false, fmt.Sprintf("no allow grants %q on %q", act, req.Resource)
		}
	}
	return true, ""
}

func artifactoryActionCovered(allows []core.Allow, res core.Resource, want core.Action) bool {
	wantLvl, ok := parseArtifactoryLevel(string(want))
	if !ok {
		return false
	}
	for _, allow := range allows {
		if !matchAnyPattern(allow.Resources, res) {
			continue
		}
		for _, act := range allow.Actions {
			if actLvl, ok := parseArtifactoryLevel(string(act)); ok && actLvl >= wantLvl {
				return true
			}
		}
	}
	return false
}

func (Artifactory) CompareLevel(a, b core.Action) (int, error) {
	levelA, okA := parseArtifactoryLevel(string(a))
	levelB, okB := parseArtifactoryLevel(string(b))
	if !okA || !okB {
		return 0, fmt.Errorf("cannot compare actions %q and %q", a, b)
	}
	switch {
	case levelA < levelB:
		return -1, nil
	case levelA > levelB:
		return +1, nil
	default:
		return 0, nil
	}
}

func (Artifactory) ValidateResourcePattern(pattern string) error {
	// same as GitHub, maybe extract into shared function :)
	r := core.Resource(pattern)
	if _, ok := r.Realm(); !ok {
		return fmt.Errorf("pattern %q missing realm prefix", pattern)
	}
	if r.Body() == "" {
		return fmt.Errorf("pattern %q is missing body", pattern)
	}
	if err := validGlob(pattern); err != nil {
		return fmt.Errorf("invalid glob in pattern %q: %w", pattern, err)
	}
	return nil
}
