package realm

import (
	"path"
	"slices"

	"github.com/darmiel/talmi/internal/core"
)

// matchPattern reports whether a glob pattern matches a full realm:body resource.
// It does NOT cross '/', meaning:
// "r:acme/*" matches "r:acme/x" but not "r:acme/x/y".
func matchPattern(pattern string, res core.Resource) bool {
	ok, err := path.Match(pattern, string(res))
	return err == nil && ok
}

// matchAnyPattern reports whether any of the patterns matches the resource
func matchAnyPattern(patterns []string, res core.Resource) bool {
	return slices.ContainsFunc(patterns, func(p string) bool {
		return matchPattern(p, res)
	})
}

// validGlob returns an error if pattern is not a syntactically valid glob.
func validGlob(pattern string) error {
	_, err := path.Match(pattern, "")
	return err
}
