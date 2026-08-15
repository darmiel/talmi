package cmd

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/darmiel/talmi/internal/core"
	"github.com/darmiel/talmi/internal/resolver"
	"github.com/darmiel/talmi/pkg/client"
)

func TestProviderList(t *testing.T) {
	t.Parallel()
	is := assert.New(t)
	must := require.New(t)

	fc := &fakeClient{
		providersFn: func(context.Context) ([]client.ProviderInfo, string, error) {
			return []client.ProviderInfo{
				{
					Name: "gh-ro", Realm: "ghes-corp", Type: "github-app", Mode: "api",
					Resources:  []string{"ghes-corp:acme/*", "ghes-corp:beta/*", "ghes-corp:platform/*"},
					MaxActions: []string{"contents:read", "metadata:read"},
				},
				{Name: "broken", Realm: "ghes-corp", Type: "github-app", Mode: "api", Error: "api down"},
				{Name: "empty", Realm: "artifactory", Type: "artifactory", Mode: "static"},
			}, "", nil
		},
	}
	deps, out, _ := testDeps(fc)
	cmd := newProviderCmd(deps)
	cmd.SetArgs([]string{"list"})
	must.NoError(cmd.Execute())

	body := out.String()
	is.Contains(body, "gh-ro")
	is.Contains(body, "ghes-corp \u00b7 github-app \u00b7 api")
	is.Contains(body, "api down")

	// long lists render one item per line, not comma-joined into a column
	lines := strings.Split(body, "\n")
	is.True(hasLineWithSuffix(lines, "ghes-corp:acme/*"))
	is.True(hasLineWithSuffix(lines, "ghes-corp:beta/*"))
	is.True(hasLineWithSuffix(lines, "ghes-corp:platform/*"))
	is.NotContains(body, "ghes-corp:acme/*, ghes-corp:beta/*", "lists must not be comma-joined")

	// a provider with no declared lists shows (none), not a blank
	is.Contains(body, "(none)")
}

func hasLineWithSuffix(lines []string, suffix string) bool {
	for _, l := range lines {
		if strings.HasSuffix(strings.TrimRight(l, " "), suffix) {
			return true
		}
	}
	return false
}

func TestProviderResolve(t *testing.T) {
	t.Parallel()
	is := assert.New(t)
	must := require.New(t)

	fc := &fakeClient{
		resolveFn: func(_ context.Context, _ []client.ResourceRequest) ([]resolver.RequestResolution, string, error) {
			return []resolver.RequestResolution{
				{
					Resource: "ghes-corp:acme/x", Actions: []core.Action{"contents:read"},
					Realm: "ghes-corp", Chosen: "gh-ro",
					Candidates: []resolver.CandidateResolution{
						{Provider: "gh-ro", Covered: true},
						{Provider: "gh-rw", Covered: false, Reason: "ceiling exceeds request"},
					},
				},
			}, "", nil
		},
	}
	deps, out, _ := testDeps(fc)

	t.Run("concise shows chosen provider", func(t *testing.T) {
		cmd := newProviderCmd(deps)
		cmd.SetArgs([]string{"resolve", "ghes-corp:acme/x=contents:read"})
		must.NoError(cmd.Execute())
		body := out.String()
		is.Contains(body, "ghes-corp:acme/x = contents:read")
		is.Contains(body, "gh-ro")
		is.NotContains(body, "gh-rw", "candidate breakdown is hidden without --verbose")
	})

	t.Run("verbose shows candidate breakdown with reasons", func(t *testing.T) {
		out.Reset()
		cmd := newProviderCmd(deps)
		cmd.SetArgs([]string{"resolve", "--verbose", "ghes-corp:acme/x=contents:read"})
		must.NoError(cmd.Execute())
		body := out.String()
		is.Contains(body, "gh-ro")
		is.Contains(body, "gh-rw")
		is.Contains(body, "ceiling exceeds request")
	})
}
