package resolver

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/darmiel/talmi/internal/core"
	"github.com/darmiel/talmi/internal/providers/stub"
	"github.com/darmiel/talmi/internal/realm"
)

func ghRealms() *realm.Registry {
	reg := realm.NewRegistry()
	reg.Register("ghes-corp", realm.GitHub{})
	reg.Register("artifactory", realm.Artifactory{})
	return reg
}

func readReq(res core.Resource, actions ...core.Action) core.ResourceRequest {
	return core.ResourceRequest{Resource: res, Actions: actions}
}

func TestResolveLeastPrivilege(t *testing.T) {
	t.Parallel()

	ro := stub.New("gh-ro", "ghes-corp",
		stub.WithResources("ghes-corp:acme/*"),
		stub.WithMaxActions("contents:read"))
	rw := stub.New("gh-rw", "ghes-corp",
		stub.WithResources("ghes-corp:acme/*"),
		stub.WithMaxActions("contents:write"))
	r := New([]core.ResourceProvider{ro, rw}, ghRealms())

	t.Run("read picks the read-only provider", func(t *testing.T) {
		t.Parallel()
		is := assert.New(t)
		minted, err := r.Resolve(context.Background(), &core.Principal{ID: "p"},
			[]core.ResourceRequest{readReq("ghes-corp:acme/x", "contents:read")})
		is.NoError(err)
		require.Len(t, minted, 1)
		is.Equal("gh-ro", minted[0].Provider) // tighter fit wins
	})

	t.Run("write picks the only capable (write) provider", func(t *testing.T) {
		t.Parallel()
		is := assert.New(t)
		minted, err := r.Resolve(context.Background(), &core.Principal{ID: "p"},
			[]core.ResourceRequest{readReq("ghes-corp:acme/x", "contents:write")})
		is.NoError(err)
		require.Len(t, minted, 1)
		is.Equal("gh-rw", minted[0].Provider)
	})
}

func TestResolveGroupsAcrossProviders(t *testing.T) {
	t.Parallel()
	is := assert.New(t)

	gh := stub.New("gh", "ghes-corp", stub.WithResources("ghes-corp:acme/*"), stub.WithMaxActions("contents:read"))
	art := stub.New("art", "artifactory", stub.WithResources("artifactory:docker-*"), stub.WithMaxActions("read"))
	r := New([]core.ResourceProvider{gh, art}, ghRealms())

	minted, err := r.Resolve(context.Background(), &core.Principal{ID: "p"}, []core.ResourceRequest{
		readReq("ghes-corp:acme/x", "contents:read"),
		readReq("artifactory:docker-prod", "read"),
	})
	is.NoError(err)
	require.Len(t, minted, 2)
	providers := []string{minted[0].Provider, minted[1].Provider}
	is.ElementsMatch([]string{"gh", "art"}, providers)
}

func TestResolveNoCapableProvider(t *testing.T) {
	t.Parallel()
	is := assert.New(t)

	ro := stub.New("gh-ro", "ghes-corp", stub.WithResources("ghes-corp:acme/*"), stub.WithMaxActions("contents:read"))
	r := New([]core.ResourceProvider{ro}, ghRealms())

	_, err := r.Resolve(context.Background(), &core.Principal{ID: "p"},
		[]core.ResourceRequest{readReq("ghes-corp:acme/x", "contents:write")})
	is.Error(err)
	is.Contains(err.Error(), "no provider can serve")
}

func TestResolveUnknownRealm(t *testing.T) {
	t.Parallel()
	is := assert.New(t)

	gh := stub.New("gh", "ghes-corp", stub.WithResources("ghes-corp:acme/*"), stub.WithMaxActions("contents:read"))
	r := New([]core.ResourceProvider{gh}, ghRealms())

	_, err := r.Resolve(context.Background(), &core.Principal{ID: "p"},
		[]core.ResourceRequest{readReq("mystery:x", "read")})
	is.Error(err)
}

func TestResolveEmpty(t *testing.T) {
	t.Parallel()
	is := assert.New(t)
	r := New(nil, ghRealms())
	minted, err := r.Resolve(context.Background(), &core.Principal{ID: "p"}, nil)
	is.NoError(err)
	is.Empty(minted)
}

func TestResolveCapabilitiesError(t *testing.T) {
	t.Parallel()
	is := assert.New(t)

	boom := errors.New("api down")
	gh := stub.New("gh", "ghes-corp", stub.WithResources("ghes-corp:acme/*"),
		stub.WithMaxActions("contents:read"), stub.WithCapabilitiesError(boom))
	r := New([]core.ResourceProvider{gh}, ghRealms())

	_, err := r.Resolve(context.Background(), &core.Principal{ID: "p"},
		[]core.ResourceRequest{readReq("ghes-corp:acme/x", "contents:read")})
	is.ErrorIs(err, boom)
}

func TestResolveAtomicRollback(t *testing.T) {
	t.Parallel()
	is := assert.New(t)

	// gh mints fine (revocable); art fails to mint -> gh must be rolled back.
	gh := stub.New("gh", "ghes-corp", stub.WithResources("ghes-corp:acme/*"), stub.WithMaxActions("contents:read"))
	art := stub.New("art", "artifactory", stub.WithResources("artifactory:docker-*"),
		stub.WithMaxActions("read"), stub.WithMintError(errors.New("mint boom")))
	r := New([]core.ResourceProvider{gh, art}, ghRealms())

	_, err := r.Resolve(context.Background(), &core.Principal{ID: "p"}, []core.ResourceRequest{
		readReq("ghes-corp:acme/x", "contents:read"),
		readReq("artifactory:docker-prod", "read"),
	})
	is.Error(err)
	is.Equal([]string{"stub-gh"}, gh.Revoked(), "the successfully minted artifact must be revoked on rollback")
}

func TestPlanOnly(t *testing.T) {
	t.Parallel()

	t.Run("returns least-privilege split without minting", func(t *testing.T) {
		t.Parallel()
		is := assert.New(t)
		must := require.New(t)

		ro := stub.New("gh-ro", "ghes-corp",
			stub.WithResources("ghes-corp:acme/*"), stub.WithMaxActions("contents:read"))
		rw := stub.New("gh-rw", "ghes-corp",
			stub.WithResources("ghes-corp:acme/*"), stub.WithMaxActions("contents:write"))
		r := New([]core.ResourceProvider{ro, rw}, ghRealms())

		plans, err := r.PlanOnly(context.Background(), []core.ResourceRequest{
			readReq("ghes-corp:acme/a", "contents:read"),
			readReq("ghes-corp:acme/b", "contents:write"),
		})
		must.NoError(err)
		must.Len(plans, 2)

		byProvider := map[string]core.MintPlan{}
		for _, p := range plans {
			byProvider[p.Provider] = p
		}
		is.Contains(byProvider, "gh-ro")
		is.Contains(byProvider, "gh-rw")
		// nothing was minted: the stub records no revocations
		is.Empty(ro.Revoked())
		is.Empty(rw.Revoked())
	})

	t.Run("errors when no provider can serve", func(t *testing.T) {
		t.Parallel()
		is := assert.New(t)
		ro := stub.New("gh-ro", "ghes-corp",
			stub.WithResources("ghes-corp:acme/*"), stub.WithMaxActions("contents:read"))
		r := New([]core.ResourceProvider{ro}, ghRealms())

		_, err := r.PlanOnly(context.Background(),
			[]core.ResourceRequest{readReq("ghes-corp:acme/x", "contents:write")})
		is.Error(err)
		is.Contains(err.Error(), "no provider can serve")
	})

	t.Run("empty requests", func(t *testing.T) {
		t.Parallel()
		is := assert.New(t)
		r := New(nil, ghRealms())
		plans, err := r.PlanOnly(context.Background(), nil)
		is.NoError(err)
		is.Empty(plans)
	})
}

func TestPreview(t *testing.T) {
	t.Parallel()

	ro := stub.New("gh-ro", "ghes-corp",
		stub.WithResources("ghes-corp:acme/*"), stub.WithMaxActions("contents:read"))
	rw := stub.New("gh-rw", "ghes-corp",
		stub.WithResources("ghes-corp:acme/*"), stub.WithMaxActions("contents:write"))
	r := New([]core.ResourceProvider{ro, rw}, ghRealms())

	t.Run("reports chosen provider and candidate breakdown", func(t *testing.T) {
		t.Parallel()
		is := assert.New(t)
		must := require.New(t)

		res, err := r.Preview(context.Background(),
			[]core.ResourceRequest{readReq("ghes-corp:acme/x", "contents:read")})
		must.NoError(err)
		must.Len(res, 1)
		is.Equal(core.Resource("ghes-corp:acme/x"), res[0].Resource)
		is.Equal("ghes-corp", res[0].Realm)
		is.Equal("gh-ro", res[0].Chosen) // tighter fit wins
		is.Empty(res[0].Reason)

		byName := map[string]CandidateResolution{}
		for _, c := range res[0].Candidates {
			byName[c.Provider] = c
		}
		is.True(byName["gh-ro"].Covered)
		is.True(byName["gh-rw"].Covered) // write ceiling also covers a read request
	})

	t.Run("no capable provider records a reason and covered=false candidates", func(t *testing.T) {
		t.Parallel()
		is := assert.New(t)
		must := require.New(t)

		roOnly := New([]core.ResourceProvider{ro}, ghRealms())
		res, err := roOnly.Preview(context.Background(),
			[]core.ResourceRequest{readReq("ghes-corp:acme/x", "contents:write")})
		must.NoError(err)
		must.Len(res, 1)
		is.Equal("", res[0].Chosen)
		is.Contains(res[0].Reason, "no provider can serve")
		must.Len(res[0].Candidates, 1)
		is.False(res[0].Candidates[0].Covered)
		is.NotEmpty(res[0].Candidates[0].Reason)
	})

	t.Run("unknown realm is reported per request, not an error", func(t *testing.T) {
		t.Parallel()
		is := assert.New(t)
		must := require.New(t)
		res, err := r.Preview(context.Background(),
			[]core.ResourceRequest{readReq("mystery:x", "read")})
		must.NoError(err)
		must.Len(res, 1)
		is.Equal("", res[0].Chosen)
		is.Contains(res[0].Reason, "unknown realm")
	})
}
