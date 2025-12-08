package api

import (
	"net/http"

	"github.com/darmiel/talmi/internal/api/middleware"
	"github.com/darmiel/talmi/internal/core"
	"github.com/darmiel/talmi/internal/engine"
	"github.com/darmiel/talmi/internal/issuers"
)

type Server struct {
	engine    *engine.Engine
	issuers   *issuers.Registry
	providers map[string]core.Provider
}

func NewServer(engine *engine.Engine, issRegistry *issuers.Registry, providers map[string]core.Provider) *Server {
	return &Server{
		engine:    engine,
		issuers:   issRegistry,
		providers: providers,
	}
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("POST /v1/issue", s.handleIssue)

	return middleware.RecoverMiddleware(
		middleware.CorrelationIDMiddleware(
			middleware.LoggingMiddleware(
				mux)))
}
