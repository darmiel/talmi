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
