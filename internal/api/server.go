package api

import (
	"net/http"

	"github.com/darmiel/talmi/internal/api/middleware"
	"github.com/darmiel/talmi/internal/audit"
	"github.com/darmiel/talmi/internal/core"
	"github.com/darmiel/talmi/internal/engine"
	"github.com/darmiel/talmi/internal/issuers"
)

type Server struct {
	engine     *engine.Engine
	issuers    *issuers.Registry
	providers  map[string]core.Provider
	auditor    core.Auditor
	tokenStore core.TokenStore
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
	return &Server{
		engine:     engine,
		issuers:    issRegistry,
		providers:  providers,
		auditor:    auditor,
		tokenStore: tokenStore,
	}
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()

	// public routes
	mux.HandleFunc("GET "+HealthCheckRoute, s.handleHealth)

	// token issuer route
	mux.HandleFunc("POST "+IssueTokenRoute, s.handleIssue)

	// admin routes
	mux.HandleFunc("GET "+ListAuditsRoute, s.handleAdminAudit)
	mux.HandleFunc("GET "+ListActiveTokensRoute, s.handleAdminTokens)

	return middleware.RecoverMiddleware(
		middleware.CorrelationIDMiddleware(
			middleware.LoggingMiddleware(
				mux)))
}
