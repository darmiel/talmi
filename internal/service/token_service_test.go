package service

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/darmiel/talmi/internal/core"
	"github.com/darmiel/talmi/internal/engine"
	"github.com/darmiel/talmi/internal/providers/stub"
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

type fakeAuditor struct{ entries []core.AuditEntry }

func (a *fakeAuditor) Log(_ context.Context, entry core.AuditEntry) error {
	a.entries = append(a.entries, entry)
	return nil
}

func (a *fakeAuditor) Query(ctx context.Context, filter core.AuditFilter) ([]core.AuditEntry, error) {
	return nil, nil
}

func (a *fakeAuditor) Close() error { return nil }

type failingStore struct{ *store.MemoryLeaseStore }

func (failingStore) SaveLease(context.Context, core.Lease) error { return errors.New("db down") }

func setup(
	t *testing.T,
	principal *core.Principal,
	verifyErr error,
	providers []core.ResourceProvider,
	leaseStore core.LeaseStore,
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
	}, pm, res, leaseStore, auditor, "rev-1")
	return svc, auditor
}

func readRequest() IssueRequest {
	return IssueRequest{
		Token:     "tok",
		Resources: []core.ResourceRequest{{Resource: "ghes-corp:acme/x", Actions: []core.Action{"contents:read"}}},
	}
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
	must.Len(auditor.entries, 1)
	is.True(auditor.entries[0].Success)
}

func TestIssueLeaseDenied(t *testing.T) {
	t.Parallel()
	is := assert.New(t)
	principal := &core.Principal{ID: "p", Issuer: "fake"}
	gh := stub.New("gh-ro", "ghes-corp", stub.WithResources("ghes-corp:acme/*"), stub.WithMaxActions("contents:read"))
	svc, auditor := setup(t, principal, nil, []core.ResourceProvider{gh}, store.NewMemoryLeaseStore())

	req := readRequest()
	req.Resources[0].Actions = []core.Action{"contents:write"} // not covered by policy
	_, err := svc.IssueLease(context.Background(), req)
	is.Error(err)
	is.False(auditor.entries[0].Success)
	is.Equal("policy denied", auditor.entries[0].Error)
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
		m[a.Fingerprint] = a.Token
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
