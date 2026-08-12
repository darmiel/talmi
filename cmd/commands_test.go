package cmd

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/darmiel/talmi/internal/cli"
	"github.com/darmiel/talmi/internal/core"
	"github.com/darmiel/talmi/internal/tasks"
	"github.com/darmiel/talmi/pkg/client"
)

// run executes a standalone command with the given args, suppressing cobra's
// own error/usage printing so tests can inspect the returned error.
func run(cmd *cobra.Command, args ...string) error {
	cmd.SilenceErrors = true
	cmd.SilenceUsage = true
	cmd.SetArgs(args)
	return cmd.Execute()
}

func exitCode(t *testing.T, err error) int {
	t.Helper()
	var ee *cli.ExitError
	require.ErrorAs(t, err, &ee)
	return ee.Code
}

func TestVersionCmd(t *testing.T) {
	t.Parallel()

	t.Run("local human output", func(t *testing.T) {
		t.Parallel()
		d, out, _ := testDeps(&fakeClient{})
		d.RemoteAddr = func() (string, error) { return "", nil } // no server -> local build info
		require.NoError(t, run(newVersionCmd(d)))
		assert.Contains(t, out.String(), "1.2.3")
		assert.Contains(t, out.String(), "abc")
	})

	t.Run("json", func(t *testing.T) {
		t.Parallel()
		d, out, _ := testDeps(&fakeClient{})
		d.RemoteAddr = func() (string, error) { return "", nil }
		require.NoError(t, run(newVersionCmd(d), "--json"))
		var got map[string]any
		require.NoError(t, json.Unmarshal(out.Bytes(), &got))
		assert.Equal(t, "1.2.3", got["version"])
	})
}

func TestTokenInspect(t *testing.T) {
	t.Parallel()
	tokenStr, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "alice",
		"iss": "https://issuer.test",
	}).SignedString([]byte("k"))
	require.NoError(t, err)

	d, out, _ := testDeps(&fakeClient{})
	require.NoError(t, run(newTokenInspectCmd(d), "--json", tokenStr))
	var claims map[string]any
	require.NoError(t, json.Unmarshal(out.Bytes(), &claims))
	assert.Equal(t, "alice", claims["sub"])
}

func TestTokenInspectRejectsGarbage(t *testing.T) {
	t.Parallel()
	d, _, _ := testDeps(&fakeClient{})
	err := run(newTokenInspectCmd(d), "not-a-jwt")
	assert.Equal(t, cli.CodeUsage, exitCode(t, err))
}

func TestTokenFingerprintRaw(t *testing.T) {
	t.Parallel()
	d, out, _ := testDeps(&fakeClient{})
	require.NoError(t, run(newTokenFingerprintCmd(d), "--type", "github", "-r", "ghs_example"))
	assert.NotEmpty(t, strings.TrimSpace(out.String()))
	assert.NotContains(t, out.String(), "Fingerprint") // raw prints only the value
}

func TestLeaseIssueJSON(t *testing.T) {
	t.Parallel()
	fake := &fakeClient{
		issueFn: func(_ context.Context, _ string, _ client.IssueRequestBody) (*client.IssueResponse, string, error) {
			return &client.IssueResponse{
				LeaseID:   "lease-1",
				Artifacts: []client.IssuedArtifact{{ArtifactID: "a1", Provider: "github", Realm: "gh"}},
			}, "corr", nil
		},
	}
	d, out, _ := testDeps(fake)
	require.NoError(t, run(newLeaseIssueCmd(d), "--json", "--resource", "gh:acme/x=contents:read", "--token", "tok"))
	var resp map[string]any
	require.NoError(t, json.Unmarshal(out.Bytes(), &resp))
	assert.Equal(t, "lease-1", resp["lease_id"])
}

func TestLeaseIssueRejectsMissingResources(t *testing.T) {
	t.Parallel()
	d, _, _ := testDeps(&fakeClient{})
	err := run(newLeaseIssueCmd(d), "--token", "tok")
	assert.Equal(t, cli.CodeUsage, exitCode(t, err))
}

func TestLeaseRevokeRefusesWithoutConfirmation(t *testing.T) {
	t.Parallel()
	// non-TTY (test streams) without --yes must fail closed.
	d, _, _ := testDeps(&fakeClient{})
	err := run(newLeaseRevokeCmd(d), "--secret", "s")
	assert.Equal(t, cli.CodeUsage, exitCode(t, err))
}

func TestLeaseRevokeWithYes(t *testing.T) {
	t.Parallel()
	called := false
	fake := &fakeClient{
		revokeFn: func(_ context.Context, _ string, _ map[string]string) (*client.RevokeResponse, string, error) {
			called = true
			return &client.RevokeResponse{LeaseID: "l1", Revoked: []string{"a"}}, "", nil
		},
	}
	d, _, errOut := testDeps(fake)
	require.NoError(t, run(newLeaseRevokeCmd(d), "--secret", "s", "--yes"))
	assert.True(t, called)
	assert.Contains(t, errOut.String(), "revoked lease l1")
}

func TestLeaseExplainReplayNotFound(t *testing.T) {
	t.Parallel()
	fake := &fakeClient{
		queryFn: func(_ context.Context, _ client.AuditFilter) ([]core.Event, string, error) {
			return nil, "", nil
		},
	}
	d, _, _ := testDeps(fake)
	err := run(newLeaseExplainCmd(d), "--replay-id", "missing")
	assert.Equal(t, cli.CodeDenied, exitCode(t, err))
}

func TestAuditList(t *testing.T) {
	t.Parallel()
	fake := &fakeClient{
		queryFn: func(_ context.Context, _ client.AuditFilter) ([]core.Event, string, error) {
			return []core.Event{
				{
					ID:      "c1",
					Action:  core.ActionLeaseIssue,
					Outcome: core.OutcomeSuccess,
					Time:    time.Now(),
					Actor:   &core.Principal{ID: "svc"},
				},
			}, "", nil
		},
	}
	d, out, _ := testDeps(fake)
	require.NoError(t, run(newAuditListCmd(d)))
	assert.Contains(t, out.String(), "svc")
	assert.Contains(t, out.String(), "lease.issue")
}

func TestAuditListInvalidSessionMapsToAuth(t *testing.T) {
	t.Parallel()
	fake := &fakeClient{
		queryFn: func(_ context.Context, _ client.AuditFilter) ([]core.Event, string, error) {
			return nil, "corr", client.ErrInvalidSession
		},
	}
	d, _, _ := testDeps(fake)
	err := run(newAuditListCmd(d))
	assert.Equal(t, cli.CodeAuth, exitCode(t, err))
}

func TestTaskListAndTrigger(t *testing.T) {
	t.Parallel()

	t.Run("list", func(t *testing.T) {
		t.Parallel()
		fake := &fakeClient{
			listFn: func(_ context.Context) ([]tasks.TaskStatus, string, error) {
				return []tasks.TaskStatus{{Name: "config-sync"}}, "", nil
			},
		}
		d, out, _ := testDeps(fake)
		require.NoError(t, run(newTaskListCmd(d)))
		assert.Contains(t, out.String(), "config-sync")
	})

	t.Run("trigger", func(t *testing.T) {
		t.Parallel()
		var got string
		fake := &fakeClient{
			triggerFn: func(_ context.Context, name string) (string, error) {
				got = name
				return "", nil
			},
		}
		d, _, errOut := testDeps(fake)
		require.NoError(t, run(newTaskTriggerCmd(d), "config-sync"))
		assert.Equal(t, "config-sync", got)
		assert.Contains(t, errOut.String(), "triggered task")
	})
}

func TestConfigSchemaEmitsJSON(t *testing.T) {
	t.Parallel()
	d, out, _ := testDeps(&fakeClient{})
	require.NoError(t, run(newConfigSchemaCmd(d), "rules"))
	var doc map[string]any
	require.NoError(t, json.Unmarshal(out.Bytes(), &doc))
	assert.NotEmpty(t, doc)
}
