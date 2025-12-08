package api

import (
	"errors"
	"net/http"
	"strings"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/darmiel/talmi/internal/api/presenter"
	"github.com/darmiel/talmi/internal/core"
	"github.com/darmiel/talmi/internal/engine"
)

// handleHealth responds with a simple OK status to indicate the server is healthy.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("OK"))
}

func (s *Server) handleIssue(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := log.Ctx(ctx)

	// read token from Authorization header
	authHeader := r.Header.Get("Authorization")
	token := strings.TrimPrefix(authHeader, "Bearer ")
	if token == "" {
		logger.Warn().Msgf("missing or empty Authorization header")
		presenter.Error(w, r, "missing Authorization header", http.StatusUnauthorized)
		return
	}

	// optional requested issuer / provider
	q := r.URL.Query()
	requestedIssuer := q.Get("issuer")
	requestedProvider := q.Get("provider")

	var issuer core.Issuer
	if requestedIssuer != "" {
		// the user specified a specific issuer
		iss, ok := s.issuers.Get(requestedIssuer)
		if !ok {
			logger.Warn().Str("requested_issuer", requestedIssuer).Msgf("requested issuer not found")
			presenter.Error(w, r, "requested issuer not found", http.StatusBadRequest)
			return
		}
		issuer = iss
		logger.Debug().Str("issuer", issuer.Name()).Msg("using explicit issuer")
	} else {
		iss, err := s.issuers.IdentifyIssuer(authHeader)
		if err != nil {
			logger.Warn().Err(err).Msgf("issuer auto-discovery failed")
			presenter.Error(w, r, "could not identify issuer from token", http.StatusBadRequest)
			return
		}
		issuer = iss
		logger.Debug().Str("issuer", issuer.Name()).Msg("using discovered issuer")
	}

	principal, err := issuer.Verify(ctx, authHeader)
	if err != nil {
		logger.Warn().Err(err).Str("issuer", issuer.Name()).Msgf("upstream token verification failed")
		presenter.Error(w, r, "token verification failed", http.StatusUnauthorized)
		return
	}

	logger.UpdateContext(func(c zerolog.Context) zerolog.Context {
		return c.Str("sub", principal.ID)
	})

	// evaluate policies
	grant, err := s.engine.Evaluate(principal, requestedProvider)
	if err != nil {
		if errors.Is(err, engine.ErrNoRuleMatch) {
			logger.Warn().Msg("policy denied")
			presenter.Error(w, r, "access denied: no matching policy rule", http.StatusForbidden)
			return
		}
		logger.Error().Err(err).Msgf("policy engine error")
		presenter.Error(w, r, "internal policy error", http.StatusInternalServerError)
		return
	}

	// find provider
	provider, ok := s.providers[grant.Provider]
	if !ok {
		logger.Error().Str("grant_provider", grant.Provider).Msg("grant references unknown provider")
		presenter.Error(w, r, "misconfiguration: provider not found", http.StatusInternalServerError)
		return
	}

	// mint token
	artifact, err := provider.Mint(ctx, principal, *grant)
	if err != nil {
		logger.Error().Err(err).Str("provider", provider.Name()).Msg("minting failed")
		presenter.Error(w, r, "token minting failed", http.StatusInternalServerError)
		return
	}

	logger.Info().
		Str("provider", provider.Name()).
		Msg("token issued successfully")

	presenter.JSON(w, r, artifact, http.StatusCreated)
}
