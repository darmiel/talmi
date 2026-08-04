package api

import (
	"net/http"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/darmiel/talmi/internal/api/presenter"
	"github.com/darmiel/talmi/internal/core"
	"github.com/darmiel/talmi/internal/issuers"
)

type sessionResponse struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

// handleLoginConfig exposes the device-flow parameters.
func (s *Server) handleLoginConfig(w http.ResponseWriter, r *http.Request) {
	presenter.JSON(w, r, s.admin.LoginInfo, http.StatusOK)
}

// handleLogin exchanges a verified GHES Oauth token for a Talmi session JWT.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	token := bearerToken(r)
	if token == "" {
		presenter.Error(w, r, "missing bearer token", http.StatusUnauthorized)
		return
	}
	issuer, ok := s.admin.LoginIssuer()
	if !ok {
		presenter.Error(w, r, "login issuer not configured", http.StatusInternalServerError)
		return
	}
	principal, err := issuer.Verify(r.Context(), token)
	if err != nil {
		log.Ctx(r.Context()).Warn().Err(err).Msg("admin.login: authentication failed")
		presenter.Error(w, r, "authentication failed", http.StatusUnauthorized)
		return
	}

	// the principal must be granted admin access by policy
	decision := s.admin.Authorize(principal, []core.ResourceRequest{
		{Resource: "talmi:session", Actions: []core.Action{"login"}},
	})
	if !decision.Authorized {
		log.Ctx(r.Context()).Warn().
			Str("sub", principal.ID).
			Str("issuer", principal.Issuer).
			Msg("admin.login: principal not authorized for admin access")
		presenter.Error(w, r, "not authorized for admin access", http.StatusForbidden)
		return
	}

	session, exp, err := issuers.IssueSession(s.admin.SessionSigner, principal, s.admin.SessionTTL)
	if err != nil {
		log.Ctx(r.Context()).Error().Err(err).
			Str("sub", principal.ID).
			Msg("admin.login: failed to issue session")
		presenter.Error(w, r, "failed to issue session", http.StatusInternalServerError)
		return
	}

	log.Ctx(r.Context()).Info().
		Str("sub", principal.ID).
		Str("issuer", principal.Issuer).
		Interface("teams", principal.Attributes["teams"]).
		Time("expires_at", exp).
		Msg("admin.login: session issued")

	presenter.JSON(w, r, sessionResponse{
		Token:     session,
		ExpiresAt: exp,
	}, http.StatusOK)
}
