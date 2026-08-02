package api

import (
	"context"
	"net/http"

	"github.com/darmiel/talmi/internal/api/middleware"
	"github.com/darmiel/talmi/internal/service"
)

type TokenService interface {
	IssueLease(ctx context.Context, req service.IssueRequest) (*service.IssueResponse, error)
	RevokeLease(ctx context.Context, req service.RevokeRequest) (*service.RevokeResponse, error)
}

type Server struct {
	current             func() TokenService
	gitHubWebhookSecret []byte
	gitHubOnWebhook     func(ctx context.Context) error
}

type Option func(*Server)

// WithGitHubWebhook enables the GitHub webhook endpoint. onReceive runs after the signature is verified.
func WithGitHubWebhook(secret []byte, onReceive func(ctx context.Context) error) Option {
	return func(server *Server) {
		server.gitHubWebhookSecret = secret
		server.gitHubOnWebhook = onReceive
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

	if s.gitHubOnWebhook != nil {
		mux.HandleFunc("POST "+WebhookGitHubRoute, s.handleGitHubWebhook)
	}

	return middleware.RecoverMiddleware(
		middleware.CorrelationIDMiddleware(
			middleware.LoggingMiddleware(mux)))
}

//type Server struct {
//	policyManager *engine.PolicyManager
//	taskManager   *tasks.Manager
//	issuers       *issuers.Registry
//	providers     map[string]core.Provider
//	auditor       core.Auditor
//	tokenStore    core.TokenStore
//	tokenService  *service.TokenService
//	config        *config.Config
//}
//
//func NewServer(
//	policyManager *engine.PolicyManager,
//	taskManager *tasks.Manager,
//	issRegistry *issuers.Registry,
//	providers map[string]core.Provider,
//	auditor core.Auditor,
//	tokenStore core.TokenStore,
//	config *config.Config,
//) *Server {
//	if auditor == nil {
//		auditor = audit.NewNoopAuditor()
//	}
//
//	svc := service.NewTokenService(issRegistry, providers, policyManager, auditor, tokenStore)
//
//	return &Server{
//		policyManager: policyManager,
//		taskManager:   taskManager,
//		issuers:       issRegistry,
//		providers:     providers,
//		auditor:       auditor,
//		tokenStore:    tokenStore,
//		tokenService:  svc,
//		config:        config,
//	}
//}
//
//const (
//	RoleAuditRead    = "audit:read"
//	RoleAuditTokens  = "audit:tokens"
//	RoleAuditExplain = "audit:explain"
//
//	RoleTaskRead    = "task:read"
//	RoleTaskTrigger = "task:trigger"
//	RoleTaskLogs    = "task:logs"
//)
//
//func withRole(role string, hf http.HandlerFunc) http.Handler {
//	return middleware.RequireRoleMiddleware(role)(hf)
//}
//
//func (s *Server) Routes(talmiSigningKey []byte) http.Handler {
//	mux := http.NewServeMux()
//
//	// public routes
//	mux.HandleFunc("GET "+HealthCheckRoute, s.handleHealth)
//	mux.HandleFunc("GET "+AboutRoute, s.handleAbout)
//
//	// token issuer route
//	mux.HandleFunc("POST "+IssueTokenRoute, s.handleIssue)
//	mux.HandleFunc("POST "+RevokeTokenRoute, s.handleRevoke) // TODO: DELETE may be better??
//
//	// webhook route
//	mux.HandleFunc("POST "+WebhookRoute, s.handleGitHubWebhook)
//
//	injectRole := middleware.InjectRoleMiddleware(talmiSigningKey)
//
//	// audit routes
//	auditMux := http.NewServeMux()
//	auditMux.Handle("GET "+ListAuditsRoute,
//		withRole(RoleAuditRead, s.handleAdminAudit))
//	auditMux.Handle("GET "+ListActiveTokensRoute,
//		withRole(RoleAuditTokens, s.handleAdminTokens))
//	auditMux.Handle("POST "+ExplainRoute,
//		withRole(RoleAuditExplain, s.handleExplain))
//	mux.Handle(AuditParent, injectRole(auditMux))
//
//	taskMux := http.NewServeMux()
//	taskMux.Handle("GET "+ListTasksRoute,
//		withRole(RoleTaskRead, s.handleListTasks))
//	taskMux.Handle("POST "+TriggerTaskRoute,
//		withRole(RoleTaskTrigger, s.handleTriggerTask))
//	taskMux.Handle("GET "+LogsForTaskRoute,
//		withRole(RoleTaskLogs, s.handleLogsForTask))
//	mux.Handle(TaskParent, injectRole(taskMux))
//
//	return middleware.RecoverMiddleware(
//		middleware.CorrelationIDMiddleware(
//			middleware.LoggingMiddleware(
//				mux)))
//}
