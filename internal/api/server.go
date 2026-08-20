package api

import (
	"context"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/darmiel/talmi/internal/api/middleware"
	"github.com/darmiel/talmi/internal/audit"
	"github.com/darmiel/talmi/internal/core"
	"github.com/darmiel/talmi/internal/issuers"
	"github.com/darmiel/talmi/internal/ratelimit"
	"github.com/darmiel/talmi/internal/resolver"
	"github.com/darmiel/talmi/internal/service"
	"github.com/darmiel/talmi/internal/tasks"
)

type TokenService interface {
	IssueLease(ctx context.Context, req service.IssueRequest) (*service.IssueResponse, error)
	RevokeLease(ctx context.Context, req service.RevokeRequest) (*service.RevokeResponse, error)
	Explain(ctx context.Context, req service.IssueRequest) (*service.ExplainResponse, error)
}

type Server struct {
	current             func() TokenService
	admin               *AdminConfig
	gitHubWebhookSecret []byte
	gitHubOnWebhook     func(ctx context.Context) error
	recorder            func() *audit.Recorder
	rateLimit           *middleware.RateLimitConfig
}

type AdminConfig struct {
	LoginIssuer   func() (core.Issuer, bool)
	SessionIssuer func() (core.Issuer, bool)
	Authorize     func(principal *core.Principal, req []core.ResourceRequest) core.Decision
	Auditor       func() core.Auditor
	SessionSigner *issuers.SessionSigner
	SessionTTL    time.Duration
	LoginInfo     LoginInfo
	Tasks         *tasks.Manager
	Providers     func() []ProviderInstance
	Preview       func(ctx context.Context, requests []core.ResourceRequest) ([]resolver.RequestResolution, error)
}

type ProviderInstance struct {
	Provider core.ResourceProvider
	Type     string
	Mode     string
}

// LoginInfo is the public device-flow config the CLI needs to start login.
type LoginInfo struct {
	Server   string   `json:"server"`
	ClientID string   `json:"client_id"`
	Scopes   []string `json:"scopes"`
}

type Option func(*Server)

// WithGitHubWebhook enables the GitHub webhook endpoint. onReceive runs after the signature is verified.
func WithGitHubWebhook(secret []byte, onReceive func(ctx context.Context) error) Option {
	return func(server *Server) {
		server.gitHubWebhookSecret = secret
		server.gitHubOnWebhook = onReceive
	}
}

func WithAdmin(cfg AdminConfig) Option {
	return func(server *Server) {
		server.admin = &cfg
	}
}

func WithRecorder(recorder func() *audit.Recorder) Option {
	return func(server *Server) {
		server.recorder = recorder
	}
}

type RateLimitOptions struct {
	Limiter   ratelimit.Limiter
	Costs     ratelimit.CostTable
	IPProfile ratelimit.Profile
	Trusted   []netip.Prefix
	Bypass    []netip.Prefix
}

func WithRateLimit(o RateLimitOptions) Option {
	return func(server *Server) {
		server.rateLimit = &middleware.RateLimitConfig{
			Limiter:     o.Limiter,
			Costs:       o.Costs,
			IPProfile:   o.IPProfile,
			Trusted:     o.Trusted,
			Bypass:      o.Bypass,
			CategoryFor: categoryForRequest,
			Exempt: func(r *http.Request) bool {
				return r.URL.Path == HealthCheckRoute || r.URL.Path == AboutRoute
			},
		}
	}
}

func NewServer(current func() TokenService, opts ...Option) *Server {
	s := &Server{
		current: current,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET "+HealthCheckRoute, s.handleHealth)
	mux.HandleFunc("GET "+AboutRoute, s.handleAbout)

	mux.HandleFunc("POST "+IssueTokenRoute, s.handleIssue)
	mux.HandleFunc("POST "+RevokeTokenRoute, s.handleRevoke)
	mux.HandleFunc("POST "+ExplainRoute, s.handleExplain)

	if s.gitHubOnWebhook != nil {
		mux.HandleFunc("POST "+WebhookGitHubRoute, s.handleGitHubWebhook)
	}

	if s.admin != nil {
		mux.HandleFunc("GET "+LoginConfigRoute, s.handleLoginConfig)
		mux.HandleFunc("POST "+LoginRoute, s.handleLogin)

		mux.HandleFunc("GET "+ProvidersRoute, s.handleProviders)
		mux.HandleFunc("POST "+ResolveRoute, s.handleResolve)

		mux.HandleFunc("GET "+AuditQueryRoute, s.handleAuditQuery)
		mux.HandleFunc("GET "+AuditEntryRoute, s.handleAuditEntry)

		if s.admin.Tasks != nil {
			mux.HandleFunc("GET "+ListTasksRoute, s.handleListTasks)
			mux.HandleFunc("POST "+TriggerTaskRoute, s.handleTriggerTask)
			mux.HandleFunc("GET "+TaskLogsRoute, s.handleTaskLogs)
		}
	}

	var handler http.Handler = mux
	if s.rateLimit != nil {
		handler = middleware.RateLimitMiddleware(*s.rateLimit)(handler)
	}
	handler = middleware.LoggingMiddleware(handler)
	handler = middleware.CorrelationIDMiddleware(handler)
	handler = middleware.RecoverMiddleware(handler)
	return handler
}

func (s *Server) record(ctx context.Context, action core.AuditAction, outcome core.Outcome, opts ...audit.Option) {
	if s.recorder == nil {
		return
	}
	rec := s.recorder()
	if rec == nil {
		return
	}
	if err := rec.Record(ctx, action, outcome, opts...); err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("audit record failed")
	}
}

func categoryForRequest(r *http.Request) ratelimit.Category {
	switch r.URL.Path {
	case IssueTokenRoute:
		return ratelimit.CategoryIssue
	case RevokeTokenRoute:
		return ratelimit.CategoryRevoke
	case ExplainRoute:
		return ratelimit.CategoryExplain
	case ProvidersRoute:
		return ratelimit.CategoryProviders
	case ResolveRoute:
		return ratelimit.CategoryResolve
	case LoginRoute:
		return ratelimit.CategorySessionLogin
	case WebhookGitHubRoute:
		return ratelimit.CategoryWebhook
	}
	switch {
	case strings.HasPrefix(r.URL.Path, AuditParent):
		return ratelimit.CategoryAudit
	case strings.HasPrefix(r.URL.Path, TaskParent):
		return ratelimit.CategoryTaskTrigger
	}
	return ratelimit.CategoryDefault
}
