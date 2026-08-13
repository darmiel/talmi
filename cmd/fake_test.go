package cmd

import (
	"bytes"
	"context"

	"github.com/darmiel/talmi/internal/buildinfo"
	"github.com/darmiel/talmi/internal/cli"
	"github.com/darmiel/talmi/internal/core"
	"github.com/darmiel/talmi/internal/tasks"
	"github.com/darmiel/talmi/pkg/client"
)

// fakeClient implements TalmiClient via optional func fields. A test only sets
// the methods it exercises; calling an unset one panics (which flags a test bug).
type fakeClient struct {
	TalmiClient
	issueFn   func(context.Context, string, client.IssueRequestBody) (*client.IssueResponse, string, error)
	revokeFn  func(context.Context, string, map[string]string) (*client.RevokeResponse, string, error)
	explainFn func(context.Context, string, client.IssueRequestBody) (*client.ExplainResponse, string, error)
	queryFn   func(context.Context, client.AuditFilter) ([]core.Event, string, error)
	inspectFn func(context.Context, string) (*core.Event, string, error)
	listFn    func(context.Context) ([]tasks.TaskStatus, string, error)
	triggerFn func(context.Context, string) (string, error)
	logsFn    func(context.Context, string) ([]tasks.LogEntry, string, error)
	infoFn    func(context.Context) (*buildinfo.Info, string, error)
}

func (f *fakeClient) IssueLease(ctx context.Context, token string, body client.IssueRequestBody) (
	*client.IssueResponse,
	string,
	error,
) {
	return f.issueFn(ctx, token, body)
}

func (f *fakeClient) RevokeLease(ctx context.Context, secret string, tokens map[string]string) (
	*client.RevokeResponse,
	string,
	error,
) {
	return f.revokeFn(ctx, secret, tokens)
}

func (f *fakeClient) Explain(ctx context.Context, token string, body client.IssueRequestBody) (
	*client.ExplainResponse,
	string,
	error,
) {
	return f.explainFn(ctx, token, body)
}

func (f *fakeClient) QueryAudit(ctx context.Context, filter client.AuditFilter) ([]core.Event, string, error) {
	return f.queryFn(ctx, filter)
}

func (f *fakeClient) InspectAudit(ctx context.Context, id string) (*core.Event, string, error) {
	return f.inspectFn(ctx, id)
}

func (f *fakeClient) ListTasks(ctx context.Context) ([]tasks.TaskStatus, string, error) {
	return f.listFn(ctx)
}

func (f *fakeClient) TriggerTask(ctx context.Context, name string) (string, error) {
	return f.triggerFn(ctx, name)
}

func (f *fakeClient) TaskLogs(ctx context.Context, name string) ([]tasks.LogEntry, string, error) {
	return f.logsFn(ctx, name)
}

func (f *fakeClient) Info(ctx context.Context) (*buildinfo.Info, string, error) {
	return f.infoFn(ctx)
}

// testDeps wires Deps to fake, non-TTY IO streams and returns the stdout and
// stderr buffers for assertions.
func testDeps(c TalmiClient) (Deps, *bytes.Buffer, *bytes.Buffer) {
	io, out, errOut := cli.TestStreams()
	d := Deps{
		IO:         io,
		Build:      buildinfo.Info{Version: "1.2.3", CommitHash: "abc"},
		NewClient:  func() (TalmiClient, error) { return c, nil },
		RemoteAddr: func() (string, error) { return "http://talmi.test", nil },
	}
	return d, out, errOut
}
