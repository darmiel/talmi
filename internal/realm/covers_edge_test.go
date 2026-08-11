package realm

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/darmiel/talmi/internal/core"
)

// allow is a tiny helper to build an Allow block.
func allow(res string, actions ...string) core.Allow {
	acts := make([]core.Action, len(actions))
	for i, a := range actions {
		acts[i] = core.Action(a)
	}
	return core.Allow{Resources: []string{res}, Actions: acts}
}

func request(res string, actions ...string) core.ResourceRequest {
	acts := make([]core.Action, len(actions))
	for i, a := range actions {
		acts[i] = core.Action(a)
	}
	return core.ResourceRequest{Resource: core.Resource(res), Actions: acts}
}

// TestCoversEmptyActionsReturnsTrue documents a sharp edge: every realm's
// Covers() returns true for a request with NO actions, because the coverage
// loop never runs. This is only safe because engine.Authorize rejects
// zero-action requests BEFORE calling Covers (TALMI-C1). If that guard is ever
// removed, this behavior becomes a fail-open. Pinned here so the invariant is
// visible.
func TestCoversEmptyActionsReturnsTrue(t *testing.T) {
	t.Parallel()
	is := assert.New(t)

	// Even with an allow set that does NOT match the resource at all, empty
	// actions => vacuously covered. The engine, not the realm, is the guard.
	empty := core.ResourceRequest{Resource: "x:unmatched", Actions: nil}

	for _, sem := range []Semantics{GitHub{}, Artifactory{}, Talmi{}} {
		ok, reason := sem.Covers(nil, empty)
		is.Truef(ok, "%s.Covers with empty actions must be vacuously true (guarded by the engine)", sem.Kind())
		is.Empty(reason)
	}
}

func TestGitHubCoversLevelLadder(t *testing.T) {
	t.Parallel()
	gh := GitHub{}
	// ceiling: contents:write
	allows := []core.Allow{allow("gh:o/*", "contents:write")}

	cases := []struct {
		action string
		want   bool
	}{
		{"contents:read", true},   // write covers read
		{"contents:write", true},  // exact
		{"contents:admin", false}, // admin > write
		{"contents:none", false},  // "none" is not a valid requestable level
		{"metadata:read", false},  // different permission entirely
	}
	for _, c := range cases {
		t.Run(c.action, func(t *testing.T) {
			t.Parallel()
			ok, _ := gh.Covers(allows, request("gh:o/repo", c.action))
			assert.Equal(t, c.want, ok)
		})
	}
}

func TestArtifactoryCoversLevelLadder(t *testing.T) {
	t.Parallel()
	af := Artifactory{}

	t.Run("annotate ceiling", func(t *testing.T) {
		t.Parallel()
		allows := []core.Allow{allow("af:repo/*", "annotate")}
		read, _ := af.Covers(allows, request("af:repo/x", "read"))
		annotate, _ := af.Covers(allows, request("af:repo/x", "annotate"))
		write, _ := af.Covers(allows, request("af:repo/x", "write"))
		assert.True(t, read, "annotate covers read")
		assert.True(t, annotate, "annotate covers annotate")
		assert.False(t, write, "annotate does not cover write")
	})

	t.Run("read ceiling does not cover annotate", func(t *testing.T) {
		t.Parallel()
		allows := []core.Allow{allow("af:repo/*", "read")}
		ok, _ := af.Covers(allows, request("af:repo/x", "annotate"))
		assert.False(t, ok)
	})

	t.Run("unknown requested action is denied", func(t *testing.T) {
		t.Parallel()
		allows := []core.Allow{allow("af:repo/*", "write")}
		ok, reason := af.Covers(allows, request("af:repo/x", "delete"))
		assert.False(t, ok)
		assert.NotEmpty(t, reason)
	})

	t.Run("unknown granted action never covers", func(t *testing.T) {
		t.Parallel()
		// allow carries a bogus level; it must not satisfy any real request.
		allows := []core.Allow{allow("af:repo/*", "bogus")}
		ok, _ := af.Covers(allows, request("af:repo/x", "read"))
		assert.False(t, ok)
	})
}

func TestTalmiCoversExactAndCaseSensitive(t *testing.T) {
	t.Parallel()
	tk := Talmi{}
	allows := []core.Allow{
		allow("talmi:audit", "read"),
		allow("talmi:tasks", "read", "trigger"),
		allow("talmi:tasks/*", "read", "trigger"),
	}

	cases := []struct {
		name string
		req  core.ResourceRequest
		want bool
	}{
		{"exact action on exact resource", request("talmi:audit", "read"), true},
		{"talmi actions are NOT ordered: trigger != read", request("talmi:audit", "trigger"), false},
		{"talmi actions are case-sensitive: READ != read", request("talmi:audit", "READ"), false},
		{"glob resource covers a sub-task", request("talmi:tasks/git-sync", "trigger"), true},
		{"glob does not cross '/' for nested task", request("talmi:tasks/a/b", "trigger"), false},
		{"unknown resource denied", request("talmi:secrets", "read"), false},
		{"multi-action all-or-nothing (one missing)", request("talmi:audit", "read", "trigger"), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			ok, _ := tk.Covers(allows, c.req)
			assert.Equal(t, c.want, ok)
		})
	}
}

// TestCoversMultipleAllowsUnion verifies the union semantics inside a single
// Covers call (the resolver/engine pass the union of all matching rules' allows).
func TestCoversMultipleAllowsUnion(t *testing.T) {
	t.Parallel()
	gh := GitHub{}
	allows := []core.Allow{
		allow("gh:o/*", "contents:read"),
		allow("gh:o/svc-*", "actions:write"),
	}
	// svc-a: contents:read from first allow, actions:write from second -> both covered.
	ok, _ := gh.Covers(allows, request("gh:o/svc-a", "contents:read", "actions:write"))
	assert.True(t, ok)

	// lib: only contents:read applies; actions:write is not granted -> denied.
	ok, _ = gh.Covers(allows, request("gh:o/lib", "contents:read", "actions:write"))
	assert.False(t, ok)
}

// TestCoversResourceIsMatchedLiterally confirms glob metacharacters in the
// requested resource are treated literally, not as a wildcard that could widen
// scope.
func TestCoversResourceIsMatchedLiterally(t *testing.T) {
	t.Parallel()
	gh := GitHub{}

	// An exact allow "gh:o/foo" must NOT be widened by a request for "gh:o/*".
	exact := []core.Allow{allow("gh:o/foo", "contents:read")}
	ok, _ := gh.Covers(exact, request("gh:o/*", "contents:read"))
	assert.False(t, ok, "a literal '*' request must not match an exact allow")

	// A glob allow "gh:o/*" DOES match the literal "*" name (path.Match treats
	// the name literally); documented, harmless because minting would fail.
	glob := []core.Allow{allow("gh:o/*", "contents:read")}
	ok, _ = gh.Covers(glob, request("gh:o/*", "contents:read"))
	assert.True(t, ok)
}

// TestRegisterOnZeroValueRegistry covers the lazy-init branch in Register that
// NewRegistry never triggers.
func TestRegisterOnZeroValueRegistry(t *testing.T) {
	t.Parallel()
	var reg Registry // zero value: byRealm is nil
	reg.Register("gh", GitHub{})
	sem, ok := reg.Get("gh")
	assert.True(t, ok)
	assert.Equal(t, KindGitHub, sem.Kind())
}

// TestValidateResourcePatternAcrossRealms fills the remaining branches of the
// per-realm pattern validators.
func TestValidateResourcePatternAcrossRealms(t *testing.T) {
	t.Parallel()
	for _, sem := range []Semantics{GitHub{}, Artifactory{}, Talmi{}} {
		sem := sem
		t.Run(sem.Kind(), func(t *testing.T) {
			t.Parallel()
			is := assert.New(t)
			is.NoError(sem.ValidateResourcePattern("realm:body/*"))
			is.Error(sem.ValidateResourcePattern("no-colon"), "missing realm prefix must error")
			is.Error(sem.ValidateResourcePattern("realm:"), "missing body must error")
			is.Error(sem.ValidateResourcePattern("realm:["), "invalid glob must error")
		})
	}
}
