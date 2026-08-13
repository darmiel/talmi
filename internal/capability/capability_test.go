package capability

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/darmiel/talmi/internal/core"
	"github.com/darmiel/talmi/internal/realm"
)

// fakeProvider is a minimal ResourceProvider + TokenRevoker whose discovered
// capability, revoke call, and invalidate call are observable.
type fakeProvider struct {
	realm        string
	discovered   core.Capability
	invalidated  bool
	revokedID    string
	requiresTok  bool
	capabilities func() (core.Capability, error)
}

func (f *fakeProvider) Name() string  { return "fake" }
func (f *fakeProvider) Realm() string { return f.realm }

func (f *fakeProvider) Capabilities(context.Context) (core.Capability, error) {
	if f.capabilities != nil {
		return f.capabilities()
	}
	return f.discovered, nil
}

func (f *fakeProvider) Plan(context.Context, []core.ResourceRequest) ([]core.MintPlan, error) {
	return nil, nil
}

func (f *fakeProvider) Mint(context.Context, *core.Principal, core.MintPlan) (*core.TokenArtifact, error) {
	return nil, nil
}

func (f *fakeProvider) Revoke(_ context.Context, revocationID, _ string) error {
	f.revokedID = revocationID
	return nil
}
func (f *fakeProvider) RequiresTokenForRevocation() bool { return f.requiresTok }
func (f *fakeProvider) Invalidate()                      { f.invalidated = true }

func TestResolveMode(t *testing.T) {
	t.Parallel()
	is := assert.New(t)
	is.Equal("static", resolveMode("static", true))
	is.Equal("api", resolveMode("api", false))
	is.Equal("api", resolveMode("", true), "unset + supports api -> api")
	is.Equal("static", resolveMode("", false), "unset + no api support -> static")
}

func TestDecorateStaticReturnsDeclared(t *testing.T) {
	t.Parallel()
	is := assert.New(t)
	must := require.New(t)

	inner := &fakeProvider{
		realm: "gh",
		discovered: core.Capability{
			Realm:      "gh",
			Resources:  []string{"gh:acme/web"},
			MaxActions: []core.Action{"contents:read"},
		},
	}
	declared := core.Capability{
		Realm:      "gh",
		Resources:  []string{"gh:acme/*"},
		MaxActions: []core.Action{"contents:read"},
	}
	p := Decorate(inner, realm.GitHub{}, "static", declared)

	got, err := p.Capabilities(context.Background())
	must.NoError(err)
	is.Equal(declared.Resources, got.Resources, "static ignores discovery, returns declared")
	is.Equal(declared.MaxActions, got.MaxActions)
}

func TestDecorateStaticSkipsDiscovery(t *testing.T) {
	t.Parallel()
	must := require.New(t)

	inner := &fakeProvider{
		realm: "gh", capabilities: func() (core.Capability, error) {
			return core.Capability{}, errors.New("discovery must not be called in static mode")
		},
	}
	declared := core.Capability{Resources: []string{"gh:acme/*"}, MaxActions: []core.Action{"contents:read"}}
	p := Decorate(inner, realm.GitHub{}, "static", declared)

	_, err := p.Capabilities(context.Background())
	must.NoError(err, "static mode must not call the inner Capabilities")
}

func TestDecorateAPIPassthrough(t *testing.T) {
	t.Parallel()
	is := assert.New(t)
	must := require.New(t)

	inner := &fakeProvider{
		realm: "gh",
		discovered: core.Capability{
			Realm:      "gh",
			Resources:  []string{"gh:acme/web"},
			MaxActions: []core.Action{"contents:read"},
		},
	}
	p := Decorate(inner, realm.GitHub{}, "api", core.Capability{}) // no ceiling

	got, err := p.Capabilities(context.Background())
	must.NoError(err)
	is.Equal([]string{"gh:acme/web"}, got.Resources)
}

func TestDecorateAPICeilingIntersects(t *testing.T) {
	t.Parallel()

	sem := realm.GitHub{}
	discovered := core.Capability{
		Realm:      "gh",
		Resources:  []string{"gh:acme/web", "gh:acme/api", "gh:other/x"},
		MaxActions: []core.Action{"contents:read", "contents:write"},
	}

	tests := []struct {
		name          string
		declared      core.Capability
		wantResources []string
		wantActions   []core.Action
	}{
		{
			name: "pattern and action ceiling",
			declared: core.Capability{
				Resources:  []string{"gh:acme/*"},
				MaxActions: []core.Action{"contents:read"},
			},
			wantResources: []string{"gh:acme/web", "gh:acme/api"},
			wantActions:   []core.Action{"contents:read"},
		},
		{
			name: "no shared actions -> empty",
			declared: core.Capability{
				Resources:  []string{"gh:acme/*"},
				MaxActions: []core.Action{"actions:write"},
			},
			wantResources: nil,
			wantActions:   nil,
		},
		{
			name: "pattern matches none -> empty resources",
			declared: core.Capability{
				Resources:  []string{"gh:nope/*"},
				MaxActions: []core.Action{"contents:read"},
			},
			wantResources: nil,
			wantActions:   []core.Action{"contents:read"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			is := assert.New(t)
			must := require.New(t)
			inner := &fakeProvider{realm: "gh", discovered: discovered}
			p := Decorate(inner, sem, "api", tt.declared)
			got, err := p.Capabilities(context.Background())
			must.NoError(err)
			is.ElementsMatch(tt.wantResources, got.Resources)
			is.ElementsMatch(tt.wantActions, got.MaxActions)
		})
	}
}

func TestDecorateForwardsInvalidate(t *testing.T) {
	t.Parallel()
	is := assert.New(t)
	inner := &fakeProvider{realm: "gh"}
	p := Decorate(inner, realm.GitHub{}, "api", core.Capability{})
	if inv, ok := p.(interface{ Invalidate() }); ok {
		inv.Invalidate()
	}
	is.True(inner.invalidated, "Invalidate must forward to the inner provider")
}

func TestDecorateForwardsRevoke(t *testing.T) {
	t.Parallel()
	is := assert.New(t)
	must := require.New(t)

	inner := &fakeProvider{realm: "gh", requiresTok: true}
	p := Decorate(inner, realm.GitHub{}, "api", core.Capability{})

	rev, ok := p.(core.TokenRevoker)
	must.True(ok, "decorated provider must remain a TokenRevoker")
	is.True(rev.RequiresTokenForRevocation())
	must.NoError(rev.Revoke(context.Background(), "rev-123", "tok"))
	is.Equal("rev-123", inner.revokedID, "Revoke must forward to the inner provider")
}
