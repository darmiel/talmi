package cmd

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/darmiel/talmi/internal/core"
	"github.com/darmiel/talmi/pkg/client"
)

func TestLeaseExplainShowsWouldMint(t *testing.T) {
	t.Parallel()
	is := assert.New(t)
	must := require.New(t)

	fc := &fakeClient{
		explainFn: func(context.Context, string, client.IssueRequestBody) (*client.ExplainResponse, string, error) {
			return &client.ExplainResponse{
				Principal: client.ExplainPrincipal{ID: "p", Issuer: "fake"},
				Decision:  core.Decision{Authorized: true},
				Plan: []core.MintPlan{
					{
						Provider: "gh", Realm: "ghes-corp", Covers: []core.ResourceRequest{
							{Resource: "ghes-corp:acme/x", Actions: []core.Action{"contents:read"}},
						},
					},
				},
			}, "", nil
		},
	}
	deps, out, _ := testDeps(fc)
	cmd := newLeaseExplainCmd(deps)
	cmd.SetArgs([]string{"--token", "tok", "--resource", "ghes-corp:acme/x=contents:read"})
	must.NoError(cmd.Execute())

	body := out.String()
	is.Contains(body, "authorized")
	is.Contains(body, "gh") // would-mint provider
	is.Contains(body, "ghes-corp:acme/x")
}

func TestLeaseExplainShowsPlanError(t *testing.T) {
	t.Parallel()
	is := assert.New(t)
	must := require.New(t)

	fc := &fakeClient{
		explainFn: func(context.Context, string, client.IssueRequestBody) (*client.ExplainResponse, string, error) {
			return &client.ExplainResponse{
				Principal: client.ExplainPrincipal{ID: "p", Issuer: "fake"},
				Decision:  core.Decision{Authorized: true},
				PlanError: "no provider can serve resource \"ghes-corp:acme/x\"",
			}, "", nil
		},
	}
	deps, out, _ := testDeps(fc)
	cmd := newLeaseExplainCmd(deps)
	cmd.SetArgs([]string{"--token", "tok", "--resource", "ghes-corp:acme/x=contents:read"})
	must.NoError(cmd.Execute())
	is.Contains(out.String(), "no provider can serve")
}
