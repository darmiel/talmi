package realm

import (
	"fmt"
	"strings"

	"github.com/darmiel/talmi/internal/core"
)

const KindGitHub = "github-app"

var _ Semantics = (*GitHub)(nil)

// GitHub implements Semantics for GitHub App permissions.
// Resources are "<realm>:<owner>/<repo>" and actions are "<permission>:<level>".
type GitHub struct{}

func (GitHub) Kind() string {
	return KindGitHub
}

// ghLevel is the local permission level ladder for GitHub.
// The order is from least to most privileged.
// DO NOT CHANGE THE ORDER!!!
type ghLevel int

const (
	ghNone ghLevel = iota
	ghRead
	ghWrite
	ghAdmin
)

func parseGitHubLevel(s string) (ghLevel, bool) {
	switch strings.ToLower(s) {
	case "read", "readonly":
		return ghRead, true
	case "write", "readwrite":
		return ghWrite, true
	case "admin":
		return ghAdmin, true
	default:
		return ghNone, false
	}
}

// parseGitHubAction splits "contents:write" into ("contents", ghWrite, true).
func parseGitHubAction(a core.Action) (perm string, lvl ghLevel, ok bool) {
	s := string(a)
	i := strings.IndexByte(s, ':')
	if i <= 0 {
		return "", ghNone, false
	}
	lvl, ok = parseGitHubLevel(s[i+1:])
	return s[:i], lvl, ok
}

func (GitHub) Covers(allows []core.Allow, req core.ResourceRequest) (bool, string) {
	for _, act := range req.Actions {
		if !gitHubActionCovered(allows, req.Resource, act) {
			return false, fmt.Sprintf("no allow grants %q on %q", act, req.Resource)
		}
	}
	return true, ""
}

// actionCovered reports whether the union of allows authorizes this exact action on the resource.
func gitHubActionCovered(allows []core.Allow, res core.Resource, want core.Action) bool {
	wantPerm, wantLvl, ok := parseGitHubAction(want)
	if !ok {
		return false
	}
	for _, allow := range allows {
		if !matchAnyPattern(allow.Resources, res) {
			continue
		}
		for _, have := range allow.Actions {
			perm, lvl, ok := parseGitHubAction(have)
			if ok && perm == wantPerm && lvl >= wantLvl {
				return true
			}
		}
	}
	return false
}

func (GitHub) CompareLevel(a, b core.Action) (int, error) {
	permA, levelA, okA := parseGitHubAction(a)
	permB, levelB, okB := parseGitHubAction(b)
	if !okA || !okB {
		return 0, fmt.Errorf("uncomparable actions: %q and %q", a, b)
	}
	if permA != permB {
		return 0, fmt.Errorf("different permissions: %q and %q", a, b)
	}
	switch {
	case levelA < levelB:
		return -1, nil
	case levelA > levelB:
		return 1, nil
	default:
		return 0, nil
	}
}

func (GitHub) ValidateResourcePattern(pattern string) error {
	r := core.Resource(pattern)
	if _, ok := r.Realm(); !ok {
		return fmt.Errorf("invalid resource pattern: missing realm prefix")
	}
	body, ok := r.Body()
	if !ok {
		// this should not happen because the check is guarded by the previous check,
		// but keep for completeness and safety :)
		return fmt.Errorf("invalid resource pattern: missing body")
	}
	if body == "" {
		return fmt.Errorf("invalid resource pattern: empty body")
	}
	// just make sure the pattern is a valid glob
	if err := validGlob(pattern); err != nil {
		return fmt.Errorf("invalid glob in pattern %q: %w", pattern, err)
	}
	return nil
}
