package stub

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/darmiel/talmi/internal/core"
)

func TestStubCapabilities(t *testing.T) {
	t.Parallel()
	is := assert.New(t)

	p := New("ro", "ghes-corp",
		WithResources("ghes-corp:acme/*"),
		WithMaxActions("contents:read"))

	capabilities, err := p.Capabilities(context.Background())
	is.NoError(err)
	is.Equal("ghes-corp", capabilities.Realm)
	is.Equal([]string{"ghes-corp:acme/*"}, capabilities.Resources)
	is.Equal([]core.Action{"contents:read"}, capabilities.MaxActions)
}

func TestStubPlan(t *testing.T) {
	t.Parallel()

	p := New("p", "ghes-corp")
	reqs := []core.ResourceRequest{
		{Resource: "ghes-corp:acme/a", Actions: []core.Action{"contents:read"}},
		{Resource: "ghes-corp:acme/b", Actions: []core.Action{"contents:write"}},
	}

	t.Run("batches all into one plan", func(t *testing.T) {
		t.Parallel()
		is := assert.New(t)

		plans, err := p.Plan(context.Background(), reqs)
		is.NoError(err)
		is.Len(plans, 1)
		is.Equal("p", plans[0].Provider)
		is.Equal("ghes-corp", plans[0].Realm)
		is.Equal(reqs, plans[0].Covers)
	})

	t.Run("empty requests yield no plans", func(t *testing.T) {
		t.Parallel()
		is := assert.New(t)

		plans, err := p.Plan(context.Background(), []core.ResourceRequest{})
		is.NoError(err)
		is.Len(plans, 0)
	})
}

func TestStubMint(t *testing.T) {
	t.Parallel()

	principal := &core.Principal{ID: "pipeline/deploy"}
	plan := core.MintPlan{
		Provider: "p",
		Realm:    "ghes-corp",
		Covers: []core.ResourceRequest{
			{Resource: "ghes-corp:acme/a", Actions: []core.Action{"contents:read"}},
		},
	}

	t.Run("deterministic and well-formed", func(t *testing.T) {
		t.Parallel()
		is := assert.New(t)
		must := require.New(t)

		p := New("p", "ghes-corp", WithTTL(2*time.Hour))

		art1, err := p.Mint(context.Background(), principal, plan)
		must.NoError(err)

		art2, err := p.Mint(context.Background(), principal, plan)
		must.NoError(err)

		is.Equal(art1.Value, art2.Value, "mint must be deterministic")
		is.NotEmpty(art1.Fingerprint)
		is.Equal("ghes-corp", art1.Metadata["realm"])
		is.WithinDuration(time.Now().Add(2*time.Hour), art1.ExpiresAt, time.Minute)
		is.Equal("stub-p", art1.RevocationID())
	})

	t.Run("mint error is returned", func(t *testing.T) {
		t.Parallel()
		is := assert.New(t)

		sentinel := fmt.Errorf("boom")
		p := New("p", "ghes-corp", WithMintError(sentinel))
		_, err := p.Mint(context.Background(), principal, plan)
		is.ErrorIs(err, sentinel)
	})
}

func TestStubRevoke(t *testing.T) {
	t.Parallel()

	t.Run("records revocation id", func(t *testing.T) {
		t.Parallel()
		is := assert.New(t)

		p := New("p", "ghes-corp")
		is.NoError(p.Revoke(context.Background(), "stub-p", "tok"))
		is.Equal([]string{"stub-p"}, p.Revoked())
	})

	t.Run("revoke error is returned and not recorded", func(t *testing.T) {
		t.Parallel()
		is := assert.New(t)

		sentinel := fmt.Errorf("boom")
		p := New("p", "ghes-corp", WithRevokeError(sentinel))
		is.ErrorIs(p.Revoke(context.Background(), "stub-p", "tok"), sentinel)
		is.Empty(p.Revoked())
	})
}
