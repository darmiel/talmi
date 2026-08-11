package engine

import (
	"testing"

	"github.com/expr-lang/expr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/darmiel/talmi/internal/core"
	"github.com/darmiel/talmi/internal/realm"
)

// This file exhaustively exercises the authorization decision surface:
// "who can request which resources, with which actions". It is intentionally
// paranoid - the whole security posture of the STS rests on Authorize().

// multiRealmEngine registers all three realm kinds under short realm names so
// tests can mix GitHub (perm:level), Artifactory (bare level) and Talmi (exact
// action) semantics in a single policy.
func multiRealmEngine(rules []core.Rule) *Engine {
	reg := realm.NewRegistry()
	reg.Register("gh", realm.GitHub{})
	reg.Register("af", realm.Artifactory{})
	reg.Register("talmi", realm.Talmi{})
	return New(rules, reg)
}

func req(resource string, actions ...string) core.ResourceRequest {
	acts := make([]core.Action, len(actions))
	for i, a := range actions {
		acts[i] = core.Action(a)
	}
	return core.ResourceRequest{Resource: core.Resource(resource), Actions: acts}
}

// realisticPolicy is a small but representative multi-issuer, multi-realm policy
// used by the matrix test below.
func realisticPolicy() []core.Rule {
	return []core.Rule{
		{ // any CI job may read acme repos
			Name:  "gh-ci-read",
			Match: core.Match{Issuer: "ci", AllowEmptyCondition: true},
			Allow: []core.Allow{{Resources: []string{"gh:acme/*"}, Actions: []core.Action{"contents:read"}}},
		},
		{ // only platform-team CI may write to service repos
			Name: "gh-ci-write-svc",
			Match: core.Match{
				Issuer:    "ci",
				Condition: &core.Condition{Key: "team", Operator: core.OpEqual, Value: "platform"},
			},
			Allow: []core.Allow{{
				Resources: []string{"gh:acme/svc-*"},
				Actions:   []core.Action{"contents:write", "actions:write"},
			}},
		},
		{ // any CI job may read the docker-local artifactory repo
			Name:  "af-ci-read",
			Match: core.Match{Issuer: "ci", AllowEmptyCondition: true},
			Allow: []core.Allow{{Resources: []string{"af:docker-local/*"}, Actions: []core.Action{"read"}}},
		},
		{ // GitHub humans in org/admins get the admin console
			Name: "talmi-admins",
			Match: core.Match{
				Issuer:    "gh-human",
				Condition: &core.Condition{Key: "teams", Operator: core.OpContains, Value: "org/admins"},
			},
			Allow: []core.Allow{
				{Resources: []string{"talmi:session"}, Actions: []core.Action{"login"}},
				{Resources: []string{"talmi:audit"}, Actions: []core.Action{"read"}},
				{Resources: []string{"talmi:tasks", "talmi:tasks/*"}, Actions: []core.Action{"read", "trigger"}},
			},
		},
	}
}

func TestAuthorizeMatrix(t *testing.T) {
	t.Parallel()
	e := multiRealmEngine(realisticPolicy())

	ciPlain := &core.Principal{ID: "job", Issuer: "ci"}
	ciPlatform := &core.Principal{ID: "job", Issuer: "ci", Attributes: map[string]any{"team": "platform"}}
	admin := &core.Principal{ID: "alice", Issuer: "gh-human", Attributes: map[string]any{"teams": []string{"org/devs", "org/admins"}}}
	nonAdmin := &core.Principal{ID: "bob", Issuer: "gh-human", Attributes: map[string]any{"teams": []string{"org/devs"}}}
	stranger := &core.Principal{ID: "eve", Issuer: "unknown-issuer"}

	tests := []struct {
		name      string
		principal *core.Principal
		requests  []core.ResourceRequest
		want      bool
	}{
		// --- CI read paths ---
		{"ci reads acme repo", ciPlain, []core.ResourceRequest{req("gh:acme/web", "contents:read")}, true},
		{"ci reads via glob under acme", ciPlain, []core.ResourceRequest{req("gh:acme/anything", "contents:read")}, true},
		{"ci cannot write without platform team", ciPlain, []core.ResourceRequest{req("gh:acme/svc-a", "contents:write")}, false},
		{"platform ci can write service repo", ciPlatform, []core.ResourceRequest{req("gh:acme/svc-a", "contents:write")}, true},
		{"platform ci cannot write a non-service repo", ciPlatform, []core.ResourceRequest{req("gh:acme/web", "contents:write")}, false},

		// --- union across rules (read rule + write-svc rule together) ---
		{"platform ci: read+write on svc via union of two rules", ciPlatform,
			[]core.ResourceRequest{req("gh:acme/svc-a", "contents:read", "actions:write")}, true},
		{"plain ci: same two-action request denied (no write rule)", ciPlain,
			[]core.ResourceRequest{req("gh:acme/svc-a", "contents:read", "actions:write")}, false},

		// --- least-scope: write covers read ---
		{"platform ci: write grant covers a read request", ciPlatform,
			[]core.ResourceRequest{req("gh:acme/svc-a", "contents:read")}, true},

		// --- too-wide: admin never granted ---
		{"ci cannot request admin (ceiling is write)", ciPlatform,
			[]core.ResourceRequest{req("gh:acme/svc-a", "contents:admin")}, false},

		// --- artifactory ---
		{"ci reads docker-local", ciPlain, []core.ResourceRequest{req("af:docker-local/img", "read")}, true},
		{"ci cannot write docker-local (only read granted)", ciPlain,
			[]core.ResourceRequest{req("af:docker-local/img", "write")}, false},
		{"ci cannot annotate docker-local (annotate > read)", ciPlain,
			[]core.ResourceRequest{req("af:docker-local/img", "annotate")}, false},

		// --- talmi admin console ---
		{"admin can login", admin, []core.ResourceRequest{req("talmi:session", "login")}, true},
		{"admin can read audit", admin, []core.ResourceRequest{req("talmi:audit", "read")}, true},
		{"admin can trigger a specific task via glob", admin, []core.ResourceRequest{req("talmi:tasks/git-sync", "trigger")}, true},
		{"admin cannot trigger audit (exact action set, no trigger)", admin,
			[]core.ResourceRequest{req("talmi:audit", "trigger")}, false},
		{"non-admin denied the admin console", nonAdmin, []core.ResourceRequest{req("talmi:session", "login")}, false},

		// --- cross-principal / cross-issuer ---
		{"stranger from unknown issuer gets nothing", stranger, []core.ResourceRequest{req("gh:acme/web", "contents:read")}, false},
		{"ci cannot use the admin console (wrong issuer)", ciPlatform, []core.ResourceRequest{req("talmi:session", "login")}, false},
		{"admin cannot mint gh tokens (their rules only grant talmi)", admin,
			[]core.ResourceRequest{req("gh:acme/web", "contents:read")}, false},

		// --- multi-resource: all-or-nothing ---
		{"all covered -> authorized", ciPlain,
			[]core.ResourceRequest{req("gh:acme/a", "contents:read"), req("af:docker-local/x", "read")}, true},
		{"one uncovered fails the whole batch", ciPlain,
			[]core.ResourceRequest{req("gh:acme/a", "contents:read"), req("af:docker-local/x", "write")}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dec := e.Authorize(tt.principal, tt.requests)
			assert.Equalf(t, tt.want, dec.Authorized, "per-request: %+v", dec.PerRequest)
		})
	}
}

// TestAuthorizeCrossRealmIsolation ensures an allow in one realm can never cover
// a resource in another realm, even when the body is identical.
func TestAuthorizeCrossRealmIsolation(t *testing.T) {
	t.Parallel()
	is := assert.New(t)

	// A rule that grants a body under realm "gh" must not cover realm "af".
	e := multiRealmEngine([]core.Rule{{
		Name:  "gh-only",
		Match: core.Match{Issuer: "ci", AllowEmptyCondition: true},
		Allow: []core.Allow{{Resources: []string{"gh:acme/*"}, Actions: []core.Action{"contents:read"}}},
	}})
	p := &core.Principal{Issuer: "ci"}

	// Same body "acme/x", different realm - the af realm doesn't even understand "contents:read".
	dec := e.Authorize(p, []core.ResourceRequest{req("af:acme/x", "read")})
	is.False(dec.Authorized, "gh allow must not leak into the af realm")
}

// TestAuthorizeNoRulesDeniesEverything: an empty policy denies all real requests.
func TestAuthorizeNoRulesDeniesEverything(t *testing.T) {
	t.Parallel()
	is := assert.New(t)
	e := multiRealmEngine(nil)

	dec := e.Authorize(&core.Principal{Issuer: "ci"}, []core.ResourceRequest{req("gh:acme/x", "contents:read")})
	is.False(dec.Authorized)
	is.Empty(dec.PolicyNames)
	is.False(dec.PerRequest[0].Covered)
	is.NotEmpty(dec.PerRequest[0].Reason)
}

// TestAuthorizeMalformedAndWeirdResources documents how odd resource strings are
// handled. These are the "weird cases" an attacker might try in a request body.
func TestAuthorizeMalformedAndWeirdResources(t *testing.T) {
	t.Parallel()

	e := multiRealmEngine([]core.Rule{{
		Name:  "read",
		Match: core.Match{Issuer: "ci", AllowEmptyCondition: true},
		Allow: []core.Allow{{Resources: []string{"gh:acme/*"}, Actions: []core.Action{"contents:read"}}},
	}})
	p := &core.Principal{Issuer: "ci"}

	tests := []struct {
		name        string
		request     core.ResourceRequest
		wantCovered bool
		reasonHas   string
	}{
		{"no realm prefix", req("no-colon", "contents:read"), false, "no realm prefix"},
		{"unknown realm", req("mystery:acme/x", "contents:read"), false, "unknown realm"},
		{"empty realm prefix", req(":acme/x", "contents:read"), false, "unknown realm"},
		{"bare colon", req(":", "read"), false, "unknown realm"},
		{"empty action list", req("gh:acme/x"), false, "no actions requested"},
		{
			// A request body of "acme/../etc" has two path segments after "acme/",
			// so the single-level glob "gh:acme/*" does NOT match it. No traversal broadening.
			name:        "path-traversal-like body is not broadened by glob",
			request:     req("gh:acme/../etc", "contents:read"),
			wantCovered: false,
			reasonHas:   "no allow grants",
		},
		{
			// A request whose body literally contains glob metacharacters is matched
			// LITERALLY against the allow pattern. "gh:acme/*" (glob) matches the
			// literal "gh:acme/*" name, so this is (perhaps surprisingly) covered.
			// It cannot be minted downstream, but authz treats it as covered.
			name:        "resource body containing a literal star is matched literally",
			request:     req("gh:acme/*", "contents:read"),
			wantCovered: true,
		},
		{
			// glob does not cross '/', so a nested path is not covered by acme/*.
			name:        "nested path not covered by single-level glob",
			request:     req("gh:acme/group/repo", "contents:read"),
			wantCovered: false,
			reasonHas:   "no allow grants",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			is := assert.New(t)
			dec := e.Authorize(p, []core.ResourceRequest{tt.request})
			is.Equal(tt.wantCovered, dec.PerRequest[0].Covered)
			is.Equal(tt.wantCovered, dec.Authorized)
			if tt.reasonHas != "" {
				is.Contains(dec.PerRequest[0].Reason, tt.reasonHas)
			}
		})
	}
}

// TestAuthorizeActionEdgeCases covers action-string parsing quirks that affect
// coverage decisions.
func TestAuthorizeActionEdgeCases(t *testing.T) {
	t.Parallel()

	e := multiRealmEngine([]core.Rule{{
		Name:  "gh",
		Match: core.Match{Issuer: "ci", AllowEmptyCondition: true},
		Allow: []core.Allow{{Resources: []string{"gh:acme/*"}, Actions: []core.Action{"contents:write"}}},
	}})
	p := &core.Principal{Issuer: "ci"}

	tests := []struct {
		name    string
		action  string
		covered bool
	}{
		{"level is case-insensitive (WRITE)", "contents:WRITE", true},
		{"level is case-insensitive (Read)", "contents:Read", true},
		{"permission is case-SENSITIVE (Contents != contents)", "Contents:read", false},
		{"missing colon is not a valid action", "contents", false},
		{"empty level is invalid", "contents:", false},
		{"empty permission is invalid", ":read", false},
		{"unknown level is invalid", "contents:superuser", false},
		{"leading space in permission breaks match", " contents:read", false},
		{"triple segment: level 'write:x' is unknown", "contents:write:x", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dec := e.Authorize(p, []core.ResourceRequest{req("gh:acme/x", tt.action)})
			assert.Equal(t, tt.covered, dec.Authorized, "reason: %s", firstReason(dec))
		})
	}
}

// TestAuthorizeDuplicateAndRepeatedRequests: duplicates and repeated resources
// are each evaluated; one uncovered duplicate fails the batch.
func TestAuthorizeDuplicateRequests(t *testing.T) {
	t.Parallel()
	is := assert.New(t)
	e := multiRealmEngine([]core.Rule{{
		Name:  "read",
		Match: core.Match{Issuer: "ci", AllowEmptyCondition: true},
		Allow: []core.Allow{{Resources: []string{"gh:acme/*"}, Actions: []core.Action{"contents:read"}}},
	}})
	p := &core.Principal{Issuer: "ci"}

	// same resource twice, both read -> ok
	dec := e.Authorize(p, []core.ResourceRequest{req("gh:acme/x", "contents:read"), req("gh:acme/x", "contents:read")})
	is.True(dec.Authorized)
	is.Len(dec.PerRequest, 2)

	// duplicate action within a single request -> still covered
	dec = e.Authorize(p, []core.ResourceRequest{req("gh:acme/x", "contents:read", "contents:read")})
	is.True(dec.Authorized)

	// same resource, one read (ok) one write (denied) -> whole batch fails
	dec = e.Authorize(p, []core.ResourceRequest{req("gh:acme/x", "contents:read"), req("gh:acme/x", "contents:write")})
	is.False(dec.Authorized)
	is.True(dec.PerRequest[0].Covered)
	is.False(dec.PerRequest[1].Covered)
}

// TestAuthorizeMalformedAllowsFailClosed: rules with empty/invalid allow blocks
// must never accidentally grant anything.
func TestAuthorizeMalformedAllowsFailClosed(t *testing.T) {
	t.Parallel()
	p := &core.Principal{Issuer: "ci"}

	t.Run("allow with no resources grants nothing", func(t *testing.T) {
		t.Parallel()
		e := multiRealmEngine([]core.Rule{{
			Name:  "empty-resources",
			Match: core.Match{Issuer: "ci", AllowEmptyCondition: true},
			Allow: []core.Allow{{Resources: nil, Actions: []core.Action{"contents:read"}}},
		}})
		dec := e.Authorize(p, []core.ResourceRequest{req("gh:acme/x", "contents:read")})
		assert.False(t, dec.Authorized)
	})

	t.Run("allow with no actions grants nothing", func(t *testing.T) {
		t.Parallel()
		e := multiRealmEngine([]core.Rule{{
			Name:  "empty-actions",
			Match: core.Match{Issuer: "ci", AllowEmptyCondition: true},
			Allow: []core.Allow{{Resources: []string{"gh:acme/*"}, Actions: nil}},
		}})
		dec := e.Authorize(p, []core.ResourceRequest{req("gh:acme/x", "contents:read")})
		assert.False(t, dec.Authorized)
	})

	t.Run("invalid glob pattern in allow matches nothing (fail-closed)", func(t *testing.T) {
		t.Parallel()
		e := multiRealmEngine([]core.Rule{{
			Name:  "bad-glob",
			Match: core.Match{Issuer: "ci", AllowEmptyCondition: true},
			Allow: []core.Allow{{Resources: []string{"gh:acme/["}, Actions: []core.Action{"contents:read"}}},
		}})
		dec := e.Authorize(p, []core.ResourceRequest{req("gh:acme/x", "contents:read")})
		assert.False(t, dec.Authorized)
	})
}

// TestAuthorizeReservedContextKeysCannotBeSpoofed: a caller must not be able to
// influence iss/sub/id/issuer by presenting a token claim of the same name; the
// server-derived values always win in the evaluation context.
func TestAuthorizeReservedContextKeysCannotBeSpoofed(t *testing.T) {
	t.Parallel()
	is := assert.New(t)

	// Rule only matches when sub == "admin".
	e := multiRealmEngine([]core.Rule{{
		Name: "sub-admin",
		Match: core.Match{
			Issuer:    "ci",
			Condition: &core.Condition{Key: "sub", Operator: core.OpEqual, Value: "admin"},
		},
		Allow: []core.Allow{{Resources: []string{"gh:acme/*"}, Actions: []core.Action{"contents:read"}}},
	}})

	// Attacker's real subject is "attacker" but they smuggle a claim sub="admin".
	// EvaluationContext overwrites sub with the verified principal ID.
	attacker := &core.Principal{ID: "attacker", Issuer: "ci", Attributes: map[string]any{"sub": "admin"}}
	dec := e.Authorize(attacker, []core.ResourceRequest{req("gh:acme/x", "contents:read")})
	is.False(dec.Authorized, "a token claim named 'sub' must not override the verified principal id")
	is.NotContains(dec.PolicyNames, "sub-admin")

	// The legitimate principal whose id IS admin matches.
	legit := &core.Principal{ID: "admin", Issuer: "ci"}
	dec = e.Authorize(legit, []core.ResourceRequest{req("gh:acme/x", "contents:read")})
	is.True(dec.Authorized)
}

// TestRuleMatchesConditionExprInteraction documents the precedence rules in
// ruleMatches for the (mostly config-rejected) combinations.
func TestRuleMatchesConditionExprInteraction(t *testing.T) {
	t.Parallel()
	reg := realm.NewRegistry()
	e := New(nil, reg)

	t.Run("non-nil but empty condition falls through to allow_empty=true", func(t *testing.T) {
		t.Parallel()
		r := core.Rule{Match: core.Match{Issuer: "a", Condition: &core.Condition{}, AllowEmptyCondition: true}}
		assert.True(t, e.ruleMatches(r, &core.Principal{Issuer: "a"}))
	})
	t.Run("non-nil but empty condition with allow_empty=false does not match", func(t *testing.T) {
		t.Parallel()
		r := core.Rule{Match: core.Match{Issuer: "a", Condition: &core.Condition{}, AllowEmptyCondition: false}}
		assert.False(t, e.ruleMatches(r, &core.Principal{Issuer: "a"}))
	})
	t.Run("when both condition and expr are set, condition wins", func(t *testing.T) {
		t.Parallel()
		// condition demands env==prod; expr would always be true. Config validation
		// rejects setting both, but the engine must be deterministic regardless.
		prog, err := expr.Compile(`true`, expr.AsBool())
		require.NoError(t, err)
		r := core.Rule{Match: core.Match{
			Issuer:       "a",
			Condition:    &core.Condition{Key: "env", Operator: core.OpEqual, Value: "prod"},
			CompiledExpr: prog,
		}}
		assert.False(t, e.ruleMatches(r, &core.Principal{Issuer: "a", Attributes: map[string]any{"env": "dev"}}))
		assert.True(t, e.ruleMatches(r, &core.Principal{Issuer: "a", Attributes: map[string]any{"env": "prod"}}))
	})
}

// TestRuleMatchesExprRuntimeError forces a deterministic runtime error inside a
// compiled expression (index out of range) and asserts it is treated as a
// no-match rather than panicking or matching.
func TestRuleMatchesExprRuntimeError(t *testing.T) {
	t.Parallel()
	reg := realm.NewRegistry()
	e := New(nil, reg)

	prog, err := expr.Compile(`ctx.arr[10] == 1`, expr.AsBool())
	require.NoError(t, err)
	r := core.Rule{Match: core.Match{Issuer: "a", CompiledExpr: prog}}

	got := e.ruleMatches(r, &core.Principal{Issuer: "a", Attributes: map[string]any{"arr": []any{}}})
	assert.False(t, got, "an expression runtime error must be a no-match")
}

func firstReason(d core.Decision) string {
	if len(d.PerRequest) > 0 {
		return d.PerRequest[0].Reason
	}
	return ""
}
