package service

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/darmiel/talmi/internal/audit"
	"github.com/darmiel/talmi/internal/core"
	"github.com/darmiel/talmi/internal/correlation"
	"github.com/darmiel/talmi/internal/engine"
	"github.com/darmiel/talmi/internal/providers/stub"
	"github.com/darmiel/talmi/internal/ratelimit"
	"github.com/darmiel/talmi/internal/realm"
	"github.com/darmiel/talmi/internal/resolver"
	"github.com/darmiel/talmi/internal/store"
)

type fakeIssuer struct {
	principal *core.Principal
	err       error
}

func (fakeIssuer) Name() string { return "fake" }
func (f fakeIssuer) Verify(context.Context, string) (*core.Principal, error) {
	return f.principal, f.err
}

type fakeIssuers struct{ issuer core.Issuer }

func (f fakeIssuers) Get(string) (core.Issuer, bool) { return f.issuer, f.issuer != nil }
func (f fakeIssuers) IdentifyIssuer(string) (core.Issuer, error) {
	if f.issuer == nil {
		return nil, errors.New("no issuer")
	}
	return f.issuer, nil
}

var _ core.Auditor = (*fakeAuditor)(nil)

type fakeAuditor struct{ events []core.Event }

func (a *fakeAuditor) Log(_ context.Context, event core.Event) error {
	a.events = append(a.events, event)
	return nil
}

func (a *fakeAuditor) Query(context.Context, core.AuditFilter) ([]core.Event, error) {
	return nil, nil
}

func (a *fakeAuditor) Prune(context.Context, time.Time) (int, error) { return 0, nil }

func (a *fakeAuditor) Close() error { return nil }

type failingStore struct{ *store.MemoryLeaseStore }

func (failingStore) SaveLease(context.Context, core.Lease) error { return errors.New("db down") }

func setup(
	t *testing.T,
	principal *core.Principal,
	verifyErr error,
	providers []core.ResourceProvider,
	leaseStore core.LeaseStore,
	opts ...Option,
) (*TokenService, *fakeAuditor) {
	t.Helper()
	reg := realm.NewRegistry()
	reg.Register("ghes-corp", realm.GitHub{})

	rules := []core.Rule{
		{
			Name:  "read",
			Match: core.Match{Issuer: "fake", AllowEmptyCondition: true},
			Allow: []core.Allow{{Resources: []string{"ghes-corp:acme/*"}, Actions: []core.Action{"contents:read"}}},
		},
	}
	pm := engine.NewManager(rules, reg)
	res := resolver.New(providers, reg)
	auditor := &fakeAuditor{}
	svc := NewTokenService(fakeIssuers{
		issuer: fakeIssuer{
			principal: principal,
			err:       verifyErr,
		},
	}, pm, res, leaseStore, audit.NewRecorder(auditor), "rev-1", opts...)
	return svc, auditor
}

// spyLimiter is a ratelimit.Limiter that records charges and can be forced to reject.
type spyLimiter struct {
	allow    bool
	admitErr error
	charges  []int
}

func (s *spyLimiter) Admit(context.Context, ratelimit.Key) (ratelimit.Decision, error) {
	if s.admitErr != nil {
		return ratelimit.Decision{}, s.admitErr
	}
	return ratelimit.Decision{Allowed: s.allow, RetryAfter: time.Second, Limit: 100}, nil
}

func (s *spyLimiter) Charge(_ context.Context, _ ratelimit.Key, cost int) error {
	s.charges = append(s.charges, cost)
	return nil
}

func readRequest() IssueRequest {
	return IssueRequest{
		Token:     "tok",
		Resources: []core.ResourceRequest{{Resource: "ghes-corp:acme/x", Actions: []core.Action{"contents:read"}}},
	}
}

func TestIssueLeasePrincipalRateLimit(t *testing.T) {
	t.Parallel()

	profile := ratelimit.Profile{Capacity: 100, RefillPerSec: 1}
	costs := ratelimit.DefaultCosts()

	t.Run("over-budget principal is rejected before mint", func(t *testing.T) {
		t.Parallel()
		is := assert.New(t)
		must := require.New(t)
		principal := &core.Principal{ID: "p", Issuer: "fake"}
		gh := stub.New("gh-ro", "ghes-corp", stub.WithResources("ghes-corp:acme/*"), stub.WithMaxActions("contents:read"))
		mem := store.NewMemoryLeaseStore()
		spy := &spyLimiter{allow: false}
		svc, _ := setup(t, principal, nil, []core.ResourceProvider{gh}, mem, WithRateLimiter(spy, profile, costs))

		_, err := svc.IssueLease(context.Background(), readRequest())
		must.Error(err)
		he, ok := errors.AsType[HTTPError](err)
		must.True(ok, "want an HTTPError")
		is.Equal(http.StatusTooManyRequests, he.StatusCode)
		is.Empty(spy.charges, "a rejected request does no work and is not charged")

		active, err := mem.ListActive(context.Background())
		must.NoError(err)
		is.Empty(active, "over-budget request must not mint or persist a lease")
	})

	t.Run("clean issue charges the success cost", func(t *testing.T) {
		t.Parallel()
		is := assert.New(t)
		must := require.New(t)
		principal := &core.Principal{ID: "p", Issuer: "fake"}
		gh := stub.New("gh-ro", "ghes-corp", stub.WithResources("ghes-corp:acme/*"), stub.WithMaxActions("contents:read"))
		spy := &spyLimiter{allow: true}
		svc, _ := setup(t, principal, nil, []core.ResourceProvider{gh}, store.NewMemoryLeaseStore(),
			WithRateLimiter(spy, profile, costs))

		_, err := svc.IssueLease(context.Background(), readRequest())
		must.NoError(err)
		is.Equal([]int{costs.Cost(ratelimit.CategoryIssue, ratelimit.ClassSuccess)}, spy.charges,
			"a clean mint charges the cheap success cost")
	})

	t.Run("denied issue charges more than a clean one", func(t *testing.T) {
		t.Parallel()
		is := assert.New(t)
		must := require.New(t)
		principal := &core.Principal{ID: "p", Issuer: "fake"}
		gh := stub.New("gh-ro", "ghes-corp", stub.WithResources("ghes-corp:acme/*"), stub.WithMaxActions("contents:read"))
		spy := &spyLimiter{allow: true}
		svc, _ := setup(t, principal, nil, []core.ResourceProvider{gh}, store.NewMemoryLeaseStore(),
			WithRateLimiter(spy, profile, costs))

		req := readRequest()
		req.Resources[0].Actions = []core.Action{"contents:write"} // denied by policy
		_, err := svc.IssueLease(context.Background(), req)
		must.Error(err)
		must.Len(spy.charges, 1)
		is.Equal(costs.Cost(ratelimit.CategoryIssue, ratelimit.ClassDenied), spy.charges[0])
		is.Greater(spy.charges[0], costs.Cost(ratelimit.CategoryIssue, ratelimit.ClassSuccess),
			"a denied request costs more quota than a clean one")
	})
}

func TestIssueLeaseHappyPath(t *testing.T) {
	t.Parallel()
	is := assert.New(t)
	must := require.New(t)

	principal := &core.Principal{ID: "p", Issuer: "fake"}
	gh := stub.New("gh-ro", "ghes-corp", stub.WithResources("ghes-corp:acme/*"), stub.WithMaxActions("contents:read"))
	memStore := store.NewMemoryLeaseStore()
	svc, auditor := setup(t, principal, nil, []core.ResourceProvider{gh}, memStore)

	resp, err := svc.IssueLease(context.Background(), readRequest())
	must.NoError(err)
	must.Len(resp.Artifacts, 1)
	is.NotEmpty(resp.Artifacts[0].Token, "response must carry the token value")
	is.NotEmpty(resp.RevocationSecret, "stub is revocable, so a secret must be issued")

	// lease is persisted without the token value
	stored, err := memStore.GetLease(context.Background(), resp.LeaseID)
	must.NoError(err)
	is.Len(stored.Artifacts, 1)
	is.NotEmpty(stored.Artifacts[0].Fingerprint)
	// audit recorded success
	must.Len(auditor.events, 1)
	is.Equal(core.ActionLeaseIssue, auditor.events[0].Action)
	is.Equal(core.OutcomeSuccess, auditor.events[0].Outcome)
}

func TestIssueLeaseDenied(t *testing.T) {
	t.Parallel()
	is := assert.New(t)
	must := require.New(t)
	principal := &core.Principal{ID: "p", Issuer: "fake"}
	gh := stub.New("gh-ro", "ghes-corp", stub.WithResources("ghes-corp:acme/*"), stub.WithMaxActions("contents:read"))
	svc, auditor := setup(t, principal, nil, []core.ResourceProvider{gh}, store.NewMemoryLeaseStore())

	req := readRequest()
	req.Resources[0].Actions = []core.Action{"contents:write"} // not covered by policy
	_, err := svc.IssueLease(context.Background(), req)
	is.Error(err)
	must.Len(auditor.events, 1)
	is.Equal(core.OutcomeDenied, auditor.events[0].Outcome)
	is.NotEmpty(auditor.events[0].Error, "denied event records the deny reason")
}

func TestIssueLeaseVerificationFails(t *testing.T) {
	t.Parallel()
	svc, _ := setup(t, nil, errors.New("bad token"), nil, store.NewMemoryLeaseStore())
	_, err := svc.IssueLease(context.Background(), readRequest())
	assert.Error(t, err)
}

func TestIssueLeaseEmptyResources(t *testing.T) {
	t.Parallel()
	principal := &core.Principal{ID: "p", Issuer: "fake"}
	svc, _ := setup(t, principal, nil, nil, store.NewMemoryLeaseStore())
	_, err := svc.IssueLease(context.Background(), IssueRequest{Token: "tok"})
	assert.Error(t, err)
}

func TestIssueLeaseNoCapableProvider(t *testing.T) {
	t.Parallel()
	principal := &core.Principal{ID: "p", Issuer: "fake"}
	// policy allows read, but there is no provider for the realm -> resolver errors
	svc, _ := setup(t, principal, nil, nil, store.NewMemoryLeaseStore())
	_, err := svc.IssueLease(context.Background(), readRequest())
	assert.Error(t, err)
}

func TestIssueLeaseStoreFailureRollsBack(t *testing.T) {
	t.Parallel()
	is := assert.New(t)
	principal := &core.Principal{ID: "p", Issuer: "fake"}
	gh := stub.New("gh-ro", "ghes-corp", stub.WithResources("ghes-corp:acme/*"), stub.WithMaxActions("contents:read"))
	svc, _ := setup(t, principal, nil, []core.ResourceProvider{gh}, failingStore{store.NewMemoryLeaseStore()})

	_, err := svc.IssueLease(context.Background(), readRequest())
	is.Error(err)
	is.Equal([]string{"stub-gh-ro"}, gh.Revoked(), "minted token must be revoked when the lease cannot be persisted")
}

func issueForRevoke(t *testing.T) (*TokenService, *stub.Provider, *store.MemoryLeaseStore, *IssueResponse) {
	t.Helper()
	principal := &core.Principal{ID: "p", Issuer: "fake"}
	gh := stub.New("gh", "ghes-corp", stub.WithResources("ghes-corp:acme/*"), stub.WithMaxActions("contents:read"))
	mem := store.NewMemoryLeaseStore()
	svc, _ := setup(t, principal, nil, []core.ResourceProvider{gh}, mem)

	issued, err := svc.IssueLease(context.Background(), readRequest())
	require.NoError(t, err)
	require.NotEmpty(t, issued.RevocationSecret)
	return svc, gh, mem, issued
}

func tokensFrom(resp *IssueResponse) map[string]string {
	m := map[string]string{}
	for _, a := range resp.Artifacts {
		m[a.ArtifactID] = a.Token
	}
	return m
}

func TestRevokeLeaseSuccess(t *testing.T) {
	t.Parallel()
	is := assert.New(t)
	svc, gh, mem, issued := issueForRevoke(t)

	resp, err := svc.RevokeLease(context.Background(), RevokeRequest{
		RevocationSecret: issued.RevocationSecret,
		Tokens:           tokensFrom(issued),
	})
	is.NoError(err)
	is.Len(resp.Revoked, 1)
	is.Equal([]string{"stub-gh"}, gh.Revoked())

	active, err := mem.ListActive(context.Background())
	is.NoError(err)
	is.Empty(active, "revoked lease must no longer be active")
}

func TestRevokeEmitsAuditEvent(t *testing.T) {
	t.Parallel()
	is := assert.New(t)
	must := require.New(t)

	principal := &core.Principal{ID: "p", Issuer: "fake"}
	gh := stub.New("gh", "ghes-corp", stub.WithResources("ghes-corp:acme/*"), stub.WithMaxActions("contents:read"))
	svc, auditor := setup(t, principal, nil, []core.ResourceProvider{gh}, store.NewMemoryLeaseStore())

	issued, err := svc.IssueLease(context.Background(), readRequest())
	must.NoError(err)
	_, err = svc.RevokeLease(context.Background(), RevokeRequest{
		RevocationSecret: issued.RevocationSecret,
		Tokens:           tokensFrom(issued),
	})
	must.NoError(err)

	must.Len(auditor.events, 2, "one issue event, one revoke event")
	revoke := auditor.events[1]
	is.Equal(core.ActionLeaseRevoke, revoke.Action)
	is.Equal(core.OutcomeSuccess, revoke.Outcome)
	is.Equal(issued.LeaseID, revoke.Metadata["lease_id"])
}

func TestRevokeLeaseInvalidSecret(t *testing.T) {
	t.Parallel()
	svc, _, _, _ := issueForRevoke(t)
	_, err := svc.RevokeLease(context.Background(), RevokeRequest{RevocationSecret: "wrong"})
	assert.Error(t, err)
}

func TestRevokeLeaseProviderFailureKeepsLeaseActive(t *testing.T) {
	t.Parallel()
	is := assert.New(t)

	principal := &core.Principal{ID: "p", Issuer: "fake"}
	gh := stub.New("gh", "ghes-corp", stub.WithResources("ghes-corp:acme/*"),
		stub.WithMaxActions("contents:read"), stub.WithRevokeError(errors.New("boom")))
	mem := store.NewMemoryLeaseStore()
	svc, _ := setup(t, principal, nil, []core.ResourceProvider{gh}, mem)

	issued, err := svc.IssueLease(context.Background(), readRequest())
	require.NoError(t, err)

	_, err = svc.RevokeLease(context.Background(), RevokeRequest{
		RevocationSecret: issued.RevocationSecret,
		Tokens:           tokensFrom(issued),
	})
	is.Error(err)

	active, err := mem.ListActive(context.Background())
	is.NoError(err)
	is.Len(active, 1, "failed revocation must leave the lease active")
}

func TestRevokeLeaseIdempotent(t *testing.T) {
	t.Parallel()
	is := assert.New(t)
	svc, gh, _, issued := issueForRevoke(t)
	tokens := tokensFrom(issued)

	_, err := svc.RevokeLease(context.Background(), RevokeRequest{
		RevocationSecret: issued.RevocationSecret,
		Tokens:           tokens,
	})
	is.NoError(err)

	resp, err := svc.RevokeLease(context.Background(), RevokeRequest{
		RevocationSecret: issued.RevocationSecret,
		Tokens:           tokens,
	})
	is.NoError(err)
	is.Empty(resp.Revoked, "second revoke is a no-op")
	is.Len(gh.Revoked(), 1, "provider revoked exactly once")
}

// TestRevokeLeaseByValueRequiresToken covers by-value providers (e.g. GitHub):
// the client must return the token value, keyed by ArtifactID, to revoke.
func TestRevokeLeaseByValueRequiresToken(t *testing.T) {
	t.Parallel()
	is := assert.New(t)

	principal := &core.Principal{ID: "p", Issuer: "fake"}
	gh := stub.New("gh", "ghes-corp",
		stub.WithResources("ghes-corp:acme/*"),
		stub.WithMaxActions("contents:read"),
		stub.WithRequiresTokenForRevocation(true))
	mem := store.NewMemoryLeaseStore()
	svc, _ := setup(t, principal, nil, []core.ResourceProvider{gh}, mem)

	issued, err := svc.IssueLease(context.Background(), readRequest())
	require.NoError(t, err)
	require.Len(t, issued.Artifacts, 1)
	is.True(issued.Artifacts[0].RequiresTokenForRevocation)
	is.NotEmpty(issued.Artifacts[0].ArtifactID)

	// Without the token, revocation must fail and leave the lease active.
	_, err = svc.RevokeLease(context.Background(), RevokeRequest{
		RevocationSecret: issued.RevocationSecret,
	})
	is.ErrorContains(err, "missing token for artifact")
	is.Empty(gh.Revoked(), "provider must not be called without the token")

	active, err := mem.ListActive(context.Background())
	require.NoError(t, err)
	is.Len(active, 1, "failed revocation must leave the lease active")

	// With the token (keyed by ArtifactID), revocation succeeds.
	resp, err := svc.RevokeLease(context.Background(), RevokeRequest{
		RevocationSecret: issued.RevocationSecret,
		Tokens:           tokensFrom(issued),
	})
	is.NoError(err)
	is.Equal([]string{issued.Artifacts[0].ArtifactID}, resp.Revoked)
	is.Len(gh.Revoked(), 1)
}

// TestRevokeLeasePartialFailureIsResumable verifies that when one artifact's
// provider revoke fails, the artifacts that DID revoke are persisted as revoked,
// so a retry skips them (resumable / idempotent revocation).
func TestRevokeLeasePartialFailureIsResumable(t *testing.T) {
	t.Parallel()
	is := assert.New(t)

	principal := &core.Principal{ID: "p", Issuer: "fake"}

	reg := realm.NewRegistry()
	reg.Register("ra", realm.GitHub{})
	reg.Register("rb", realm.GitHub{})

	ok := stub.New("ok", "ra",
		stub.WithResources("ra:acme/*"), stub.WithMaxActions("contents:read"))
	bad := stub.New("bad", "rb",
		stub.WithResources("rb:acme/*"), stub.WithMaxActions("contents:read"),
		stub.WithRevokeError(errors.New("boom")))

	rules := []core.Rule{
		{
			Name:  "read",
			Match: core.Match{Issuer: "fake", AllowEmptyCondition: true},
			Allow: []core.Allow{
				{Resources: []string{"ra:acme/*"}, Actions: []core.Action{"contents:read"}},
				{Resources: []string{"rb:acme/*"}, Actions: []core.Action{"contents:read"}},
			},
		},
	}
	pm := engine.NewManager(rules, reg)
	res := resolver.New([]core.ResourceProvider{ok, bad}, reg)
	mem := store.NewMemoryLeaseStore()
	svc := NewTokenService(
		fakeIssuers{issuer: fakeIssuer{principal: principal}},
		pm, res, mem, audit.NewRecorder(&fakeAuditor{}), "rev-1",
	)

	issued, err := svc.IssueLease(context.Background(), IssueRequest{
		Token: "tok",
		Resources: []core.ResourceRequest{
			{Resource: "ra:acme/x", Actions: []core.Action{"contents:read"}},
			{Resource: "rb:acme/y", Actions: []core.Action{"contents:read"}},
		},
	})
	require.NoError(t, err)
	require.Len(t, issued.Artifacts, 2)

	// First revoke: "bad" fails, so the overall revoke errors.
	_, err = svc.RevokeLease(context.Background(), RevokeRequest{RevocationSecret: issued.RevocationSecret})
	is.Error(err)
	is.Len(ok.Revoked(), 1, "the good provider was revoked once")
	is.Empty(bad.Revoked(), "the failing provider recorded nothing")

	// The good artifact must be persisted as revoked; the bad one still active.
	lease, err := mem.GetLease(context.Background(), issued.LeaseID)
	require.NoError(t, err)
	revoked := map[string]bool{}
	for _, a := range lease.Artifacts {
		revoked[a.Provider] = a.Revoked
	}
	is.True(revoked["ok"], "successfully revoked artifact must be persisted as revoked")
	is.False(revoked["bad"], "failed artifact must remain active for retry")

	// Second revoke: the good artifact is skipped (not revoked again); bad is retried.
	_, err = svc.RevokeLease(context.Background(), RevokeRequest{RevocationSecret: issued.RevocationSecret})
	is.Error(err)
	is.Len(ok.Revoked(), 1, "already-revoked artifact must not be revoked again")
}

// TestIssueNestsArtifactsInAudit verifies that a lease issue writes exactly ONE
// audit entry per request, with the minted artifacts (and their fingerprints)
// nested inside it - never one entry per artifact.
func TestIssueNestsArtifactsInAudit(t *testing.T) {
	t.Parallel()
	is := assert.New(t)

	principal := &core.Principal{ID: "p", Issuer: "fake"}
	reg := realm.NewRegistry()
	reg.Register("ghes-corp", realm.GitHub{})
	gh := stub.New("gh", "ghes-corp",
		stub.WithResources("ghes-corp:acme/*"), stub.WithMaxActions("contents:read"))
	rules := []core.Rule{
		{
			Name:  "read",
			Match: core.Match{Issuer: "fake", AllowEmptyCondition: true},
			Allow: []core.Allow{{Resources: []string{"ghes-corp:acme/*"}, Actions: []core.Action{"contents:read"}}},
		},
	}
	pm := engine.NewManager(rules, reg)
	res := resolver.New([]core.ResourceProvider{gh}, reg)
	mem := store.NewMemoryLeaseStore()
	auditor := audit.NewInMemoryAuditor()
	svc := NewTokenService(
		fakeIssuers{issuer: fakeIssuer{principal: principal}},
		pm, res, mem, audit.NewRecorder(auditor), "rev-1",
	)

	issued, err := svc.IssueLease(context.Background(), readRequest())
	require.NoError(t, err)
	require.Len(t, issued.Artifacts, 1)
	fp := issued.Artifacts[0].Fingerprint
	require.NotEmpty(t, fp, "stub artifact should carry a fingerprint")

	// Exactly one entry for the whole request, with the artifact nested inside.
	all, err := auditor.Query(context.Background(), core.AuditFilter{})
	require.NoError(t, err)
	require.Len(t, all, 1, "one audit entry per request, not per artifact")
	entry := all[0]
	is.Equal(core.ActionLeaseIssue, entry.Action)
	is.Equal(core.OutcomeSuccess, entry.Outcome)
	is.Equal(issued.LeaseID, entry.Metadata["lease_id"], "the lease id is carried in metadata, not the event id")
	is.NotEqual(issued.LeaseID, entry.ID, "the event has its own id, distinct from the lease id")
	require.Len(t, entry.Artifacts, 1)
	is.Equal(issued.Artifacts[0].ArtifactID, entry.Artifacts[0].ArtifactID)
	is.Equal(fp, entry.Artifacts[0].Fingerprint)
	is.Equal("gh", entry.Artifacts[0].Provider)

	// Fingerprint filter matches the nested artifact and returns the single request entry.
	byFP, err := auditor.Query(context.Background(), core.AuditFilter{Fingerprint: fp})
	require.NoError(t, err)
	require.Len(t, byFP, 1)
	is.Equal(issued.LeaseID, byFP[0].Metadata["lease_id"])
}

// TestIssueDeniedWritesSingleAuditEntry verifies that a denied multi-resource
// request produces ONE failure entry, not one per requested resource.
func TestIssueDeniedWritesSingleAuditEntry(t *testing.T) {
	t.Parallel()
	is := assert.New(t)

	// principal from an issuer no rule matches -> every resource is denied
	principal := &core.Principal{ID: "p", Issuer: "stranger"}
	reg := realm.NewRegistry()
	reg.Register("ghes-corp", realm.GitHub{})
	gh := stub.New("gh", "ghes-corp",
		stub.WithResources("ghes-corp:acme/*"), stub.WithMaxActions("contents:read"))
	rules := []core.Rule{
		{
			Name:  "read",
			Match: core.Match{Issuer: "fake", AllowEmptyCondition: true},
			Allow: []core.Allow{{Resources: []string{"ghes-corp:acme/*"}, Actions: []core.Action{"contents:read"}}},
		},
	}
	pm := engine.NewManager(rules, reg)
	res := resolver.New([]core.ResourceProvider{gh}, reg)
	mem := store.NewMemoryLeaseStore()
	auditor := audit.NewInMemoryAuditor()
	svc := NewTokenService(
		fakeIssuers{issuer: fakeIssuer{principal: principal}},
		pm, res, mem, audit.NewRecorder(auditor), "rev-1",
	)

	reqs := make([]core.ResourceRequest, 0, 10)
	for i := range 10 {
		reqs = append(reqs, core.ResourceRequest{
			Resource: core.Resource(fmt.Sprintf("ghes-corp:acme/repo-%d", i)),
			Actions:  []core.Action{"contents:read"},
		})
	}
	_, err := svc.IssueLease(context.Background(), IssueRequest{Token: "tok", Resources: reqs})
	is.Error(err)

	all, err := auditor.Query(context.Background(), core.AuditFilter{})
	require.NoError(t, err)
	require.Len(t, all, 1, "a denied 10-resource request must write exactly one audit entry")
	is.Equal(core.OutcomeDenied, all[0].Outcome)
	is.Empty(all[0].Artifacts, "nothing minted, so no nested artifacts")
}

func TestIssueLeaseEmptyActionsDenied(t *testing.T) {
	t.Parallel()
	is := assert.New(t)

	principal := &core.Principal{ID: "p", Issuer: "fake"}
	gh := stub.New("gh-ro", "ghes-corp", stub.WithResources("ghes-corp:acme/*"), stub.WithMaxActions("contents:read"))
	svc, _ := setup(t, principal, nil, []core.ResourceProvider{gh}, store.NewMemoryLeaseStore())

	req := readRequest()
	req.Resources[0].Actions = nil // no actions requested

	_, err := svc.IssueLease(context.Background(), req)
	is.Error(err, "a request with no actions must be denied, not minted")
}

func TestRollbackUsesLiveContext_TALMI_H8(t *testing.T) {
	t.Parallel()
	is := assert.New(t)
	must := require.New(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	principal := &core.Principal{ID: "p", Issuer: "fake"}
	fake := &ctxRecordingProvider{name: "fake", realm: "ghes-corp", onMint: cancel}
	svc, _ := setup(t, principal, nil, []core.ResourceProvider{fake}, failingStore{store.NewMemoryLeaseStore()})

	_, err := svc.IssueLease(ctx, readRequest())
	must.Error(err, "store failure must fail the issue")
	must.True(fake.revokeCalled, "the minted artifact must be rolled back")

	is.NoError(fake.revokeCtxErr,
		"rollback must revoke with a non-cancelled context (use context.WithoutCancel)")
}

type ctxRecordingProvider struct {
	name, realm  string
	onMint       func()
	revokeCalled bool
	revokeCtxErr error
}

func (p *ctxRecordingProvider) Name() string  { return p.name }
func (p *ctxRecordingProvider) Realm() string { return p.realm }

func (p *ctxRecordingProvider) Capabilities(context.Context) (core.Capability, error) {
	return core.Capability{
		Realm:      p.realm,
		Resources:  []string{"ghes-corp:acme/*"},
		MaxActions: []core.Action{"contents:read"},
	}, nil
}

func (p *ctxRecordingProvider) Plan(_ context.Context, reqs []core.ResourceRequest) ([]core.MintPlan, error) {
	if len(reqs) == 0 {
		return nil, nil
	}
	return []core.MintPlan{{Provider: p.name, Realm: p.realm, Covers: reqs}}, nil
}

func (p *ctxRecordingProvider) Mint(_ context.Context, _ *core.Principal, _ core.MintPlan) (
	*core.TokenArtifact,
	error,
) {
	a := &core.TokenArtifact{
		Value:       "tok-" + p.name,
		Fingerprint: "fp-" + p.name,
		ExpiresAt:   time.Now().Add(time.Hour),
	}
	a.SetRevocationID("rev-" + p.name)
	if p.onMint != nil {
		p.onMint()
	}
	return a, nil
}

func (p *ctxRecordingProvider) Revoke(ctx context.Context, _, _ string) error {
	p.revokeCalled = true
	p.revokeCtxErr = ctx.Err()
	return nil
}

func (p *ctxRecordingProvider) RequiresTokenForRevocation() bool { return false }

func TestIssueLeaseCorrelationIDNotUsedAsLeaseID_TALMI_H1(t *testing.T) {
	t.Parallel()
	is := assert.New(t)
	must := require.New(t)

	principal := &core.Principal{ID: "p", Issuer: "fake"}
	gh := stub.New("gh-ro", "ghes-corp", stub.WithResources("ghes-corp:acme/*"), stub.WithMaxActions("contents:read"))
	mem := store.NewMemoryLeaseStore()
	svc, _ := setup(t, principal, nil, []core.ResourceProvider{gh}, mem)

	ctx := correlation.With(context.Background(), "client-chosen-id")

	r1, err := svc.IssueLease(ctx, readRequest())
	must.NoError(err)
	r2, err := svc.IssueLease(ctx, readRequest())
	must.NoError(err)

	is.NotEqual(r1.LeaseID, r2.LeaseID,
		"lease IDs must be server-generated and unique, not derived from the client correlation id")

	// Neither lease may be lost to an overwrite.
	active, err := mem.ListActive(context.Background())
	must.NoError(err)
	is.Len(active, 2, "both issued leases must be tracked; none overwritten")
}

func TestExplainIncludesPlan(t *testing.T) {
	t.Parallel()
	is := assert.New(t)
	must := require.New(t)

	principal := &core.Principal{ID: "p", Issuer: "fake"}
	gh := stub.New("gh", "ghes-corp",
		stub.WithResources("ghes-corp:acme/*"), stub.WithMaxActions("contents:read"))
	svc, _ := setup(t, principal, nil, []core.ResourceProvider{gh}, store.NewMemoryLeaseStore())

	resp, err := svc.Explain(context.Background(), IssueRequest{
		Token:     "tok",
		Resources: []core.ResourceRequest{{Resource: "ghes-corp:acme/x", Actions: []core.Action{"contents:read"}}},
	})
	must.NoError(err)
	is.True(resp.Decision.Authorized)
	is.Empty(resp.PlanError)
	must.Len(resp.Plan, 1)
	is.Equal("gh", resp.Plan[0].Provider)
}

func TestExplainPlanErrorWhenUnservable(t *testing.T) {
	t.Parallel()
	is := assert.New(t)
	must := require.New(t)

	// authorized by policy (read rule) but no provider serves this realm/actions
	principal := &core.Principal{ID: "p", Issuer: "fake"}
	svc, _ := setup(t, principal, nil, nil, store.NewMemoryLeaseStore())

	resp, err := svc.Explain(context.Background(), IssueRequest{
		Token:     "tok",
		Resources: []core.ResourceRequest{{Resource: "ghes-corp:acme/x", Actions: []core.Action{"contents:read"}}},
	})
	must.NoError(err)
	is.True(resp.Decision.Authorized, "policy authorizes it")
	is.Empty(resp.Plan)
	is.Contains(resp.PlanError, "no provider can serve")
}

func TestPreviewDelegates(t *testing.T) {
	t.Parallel()
	is := assert.New(t)
	must := require.New(t)

	principal := &core.Principal{ID: "p", Issuer: "fake"}
	gh := stub.New("gh", "ghes-corp",
		stub.WithResources("ghes-corp:acme/*"), stub.WithMaxActions("contents:read"))
	svc, _ := setup(t, principal, nil, []core.ResourceProvider{gh}, store.NewMemoryLeaseStore())

	res, err := svc.Preview(context.Background(),
		[]core.ResourceRequest{{Resource: "ghes-corp:acme/x", Actions: []core.Action{"contents:read"}}})
	must.NoError(err)
	must.Len(res, 1)
	is.Equal("gh", res[0].Chosen)
}
