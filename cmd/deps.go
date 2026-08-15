package cmd

import (
	"context"

	"github.com/darmiel/talmi/internal/buildinfo"
	"github.com/darmiel/talmi/internal/cli"
	"github.com/darmiel/talmi/internal/core"
	"github.com/darmiel/talmi/internal/resolver"
	"github.com/darmiel/talmi/internal/tasks"
	"github.com/darmiel/talmi/pkg/client"
)

type leaseAPI interface {
	IssueLease(ctx context.Context, token string, body client.IssueRequestBody) (*client.IssueResponse, string, error)
	RevokeLease(ctx context.Context, secret string, tokens map[string]string) (*client.RevokeResponse, string, error)
	Explain(ctx context.Context, token string, body client.IssueRequestBody) (*client.ExplainResponse, string, error)
}

type auditAPI interface {
	QueryAudit(ctx context.Context, filter client.AuditFilter) ([]core.Event, string, error)
	InspectAudit(ctx context.Context, id string) (*core.Event, string, error)
}

type taskAPI interface {
	ListTasks(ctx context.Context) ([]tasks.TaskStatus, string, error)
	TriggerTask(ctx context.Context, name string) (string, error)
	TaskLogs(ctx context.Context, name string) ([]tasks.LogEntry, string, error)
}

type sessionAPI interface {
	GetLoginInfo(ctx context.Context) (*client.LoginInfo, string, error)
	ExchangeSession(ctx context.Context, ghesToken string) (*client.SessionResponse, string, error)
}

type infoAPI interface {
	Info(ctx context.Context) (*buildinfo.Info, string, error)
}

type providerAPI interface {
	Providers(ctx context.Context) ([]client.ProviderInfo, string, error)
	Resolve(ctx context.Context, requests []client.ResourceRequest) ([]resolver.RequestResolution, string, error)
}

var _ TalmiClient = (*client.Client)(nil)

type TalmiClient interface {
	leaseAPI
	auditAPI
	taskAPI
	sessionAPI
	infoAPI
	providerAPI
}

// Deps carries dependencies for commands.
type Deps struct {
	IO    cli.IOStreams
	Build buildinfo.Info

	NewClient  func() (TalmiClient, error)
	RemoteAddr func() (string, error)
}
