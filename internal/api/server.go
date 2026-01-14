package api

import (
	"net/http"

	"github.com/darmiel/talmi/internal/api/middleware"
	"github.com/darmiel/talmi/internal/audit"
	"github.com/darmiel/talmi/internal/core"
	"github.com/darmiel/talmi/internal/engine"
	"github.com/darmiel/talmi/internal/issuers"
	"github.com/darmiel/talmi/internal/service"
)

type Server struct {
	engine       *engine.Engine
	issuers      *issuers.Registry
	providers    map[string]core.Provider
	auditor      core.Auditor
	tokenStore   core.TokenStore
	tokenService *service.TokenService
}

func NewServer(
	engine *engine.Engine,
	issRegistry *issuers.Registry,
	providers map[string]core.Provider,
	auditor core.Auditor,
	tokenStore core.TokenStore,
) *Server {
	if auditor == nil {
		auditor = audit.NewNoopAuditor()
	}

	svc := service.NewTokenService(issRegistry, providers, engine, auditor, tokenStore)

	return &Server{
		engine:       engine,
		issuers:      issRegistry,
		providers:    providers,
		auditor:      auditor,
		tokenStore:   tokenStore,
		tokenService: svc,
	}
}

func (s *Server) Routes(talmiSigningKey []byte) http.Handler {
	mux := http.NewServeMux()

	// public routes
	mux.HandleFunc("GET "+HealthCheckRoute, s.handleHealth)
	mux.HandleFunc("GET "+AboutRoute, s.handleAbout)

	// token issuer route
	mux.HandleFunc("POST "+IssueTokenRoute, s.handleIssue)

	// admin routes
	adminMux := http.NewServeMux()
	adminMux.HandleFunc("GET "+ListAuditsRoute, s.handleAdminAudit)
	adminMux.HandleFunc("GET "+ListActiveTokensRoute, s.handleAdminTokens)
	adminMux.HandleFunc("POST "+ExplainRoute, s.handleExplain)
	mux.Handle("/v1/admin/", middleware.AdminAuth(talmiSigningKey)(adminMux))

	return middleware.RecoverMiddleware(
		middleware.CorrelationIDMiddleware(
			middleware.LoggingMiddleware(
				mux)))
}
