package cmd

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/darmiel/talmi/pkg/client"
)

func sampleLease() *client.IssueResponse {
	return &client.IssueResponse{
		LeaseID:          "lease-1",
		RevocationSecret: "sekret-value",
		Artifacts: []client.IssuedArtifact{
			{
				ArtifactID:                 "art-1",
				Provider:                   "gh-writer",
				Realm:                      "ghes-corp",
				Covers:                     []string{"ghes-corp:acme/svc-a", "ghes-corp:acme/svc-b"},
				Token:                      "ghs_tokenvalue",
				Fingerprint:                "fp-abc",
				ExpiresAt:                  time.Now().Add(59 * time.Minute),
				RequiresTokenForRevocation: true,
			},
		},
	}
}

func TestLeaseIssueWithoutOutShowsSecrets(t *testing.T) {
	t.Parallel()
	is := assert.New(t)
	must := require.New(t)

	fc := &fakeClient{
		issueFn: func(context.Context, string, client.IssueRequestBody) (*client.IssueResponse, string, error) {
			return sampleLease(), "", nil
		},
	}
	deps, out, _ := testDeps(fc)
	cmd := newLeaseIssueCmd(deps)
	cmd.SetArgs([]string{"--token", "tok", "--resource", "ghes-corp:acme/svc-a=contents:write"})
	must.NoError(cmd.Execute())

	body := out.String()
	is.Contains(body, "lease lease-1")
	is.Contains(body, "ghs_tokenvalue", "the token must be printed when there is no --out")
	is.Contains(body, "sekret-value", "the revocation secret must be printed when there is no --out")
	// covers render one per line
	lines := strings.Split(body, "\n")
	is.True(hasLineWithSuffix(lines, "ghes-corp:acme/svc-a"))
	is.True(hasLineWithSuffix(lines, "ghes-corp:acme/svc-b"))
}

func TestLeaseIssueWithOutHidesSecretsAndWritesFile(t *testing.T) {
	t.Parallel()
	is := assert.New(t)
	must := require.New(t)

	dir := t.TempDir()
	leaseFile := filepath.Join(dir, "lease.json")

	fc := &fakeClient{
		issueFn: func(context.Context, string, client.IssueRequestBody) (*client.IssueResponse, string, error) {
			return sampleLease(), "", nil
		},
	}
	deps, out, errOut := testDeps(fc)
	cmd := newLeaseIssueCmd(deps)
	cmd.SetArgs([]string{"--token", "tok", "--out", leaseFile, "--resource", "ghes-corp:acme/svc-a=contents:write"})
	must.NoError(cmd.Execute())

	// stdout card must not leak the token or secret when they were written to a file
	body := out.String()
	is.Contains(body, "lease lease-1")
	is.NotContains(body, "ghs_tokenvalue")
	is.NotContains(body, "sekret-value")

	// stderr reports the file we wrote (the file path, not a directory)
	is.Contains(errOut.String(), leaseFile)

	// the file holds the full lease, tokens included
	data, err := os.ReadFile(leaseFile)
	must.NoError(err)
	is.Contains(string(data), "ghs_tokenvalue")
	is.Contains(string(data), "sekret-value")
}
