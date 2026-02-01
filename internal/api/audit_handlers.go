package api

import (
	"net/http"
	"strconv"

	"github.com/rs/zerolog/log"

	"github.com/darmiel/talmi/internal/api/presenter"
	"github.com/darmiel/talmi/internal/core"
	"github.com/darmiel/talmi/internal/service"
)

// handleAdminAudit processes requests to retrieve audit log entries.
func (s *Server) handleAdminAudit(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := log.Ctx(ctx)

	// filters
	q := r.URL.Query()
	limitStr := q.Get("limit")

	filterCorrelationID := q.Get("correlation_id")
	filterPrincipalID := q.Get("principal_id")
	filterFingerprint := q.Get("fingerprint")

	limit := 50
	if limitStr != "" {
		if v, err := strconv.Atoi(limitStr); err != nil {
			logger.Warn().Err(err).Str("limit", limitStr).Msg("invalid limit parameter")
			presenter.Error(w, r, "invalid limit parameter", http.StatusBadRequest)
			return
		} else {
			limit = v
		}
	}

	var entries []core.AuditEntry
	var err error

	if filterCorrelationID != "" || filterFingerprint != "" || filterPrincipalID != "" {
		logger.Info().Msgf("applying audit log filters")
		entries, err = s.auditor.Find(func(entry core.AuditEntry) bool {
			if filterCorrelationID != "" && entry.ID != filterCorrelationID {
				return false
			}
			if filterFingerprint != "" && entry.TokenFingerprint != filterFingerprint {
				return false
			}
			if filterPrincipalID != "" && entry.Principal.ID != filterPrincipalID {
				return false
			}
			return true
		}, limit)
	} else {
		log.Debug().Msgf("retrieving recent audit log entries")
		entries, err = s.auditor.GetRecent(limit)
	}

	if err != nil {
		logger.Error().Err(err).Msg("failed to retrieve audit logs")
		presenter.Error(w, r, "failed to retrieve audit logs", http.StatusInternalServerError)
		return
	}

	presenter.JSON(w, r, entries, http.StatusOK)
}

// handleAdminTokens processes requests to retrieve active issued tokens.
func (s *Server) handleAdminTokens(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := log.Ctx(ctx)

	tokens, err := s.tokenStore.ListActive(ctx)
	if err != nil {
		logger.Error().Err(err).Msg("failed to retrieve active tokens")
		presenter.Error(w, r, "failed to retrieve active tokens", http.StatusInternalServerError)
		return
	}

	presenter.JSON(w, r, tokens, http.StatusOK)
}

type ExplainRequest struct {
	Token    string `json:"token,omitempty"`
	ReplayID string `json:"replay_id,omitempty"`

	// Context overrides
	RequestedIssuer string        `json:"requested_issuer,omitempty"`
	Targets         []core.Target `json:"targets,omitempty"`
}

// handleExplain processes token explanation requests.
func (s *Server) handleExplain(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := log.Ctx(ctx)

	var payload ExplainRequest
	if err := DecodePayload(r, &payload, false); err != nil {
		logger.Warn().Err(err).Msg("failed to decode explain request payload")
		presenter.Error(w, r, "invalid request payload", http.StatusBadRequest)
		return
	}

	trace, err := s.tokenService.ExplainTrace(ctx, service.ExplainRequest{
		Token:           payload.Token,
		ReplayID:        payload.ReplayID,
		RequestedIssuer: payload.RequestedIssuer,
		Targets:         payload.Targets,
	})
	if err != nil {
		logger.Error().Err(err).Msg("explain failed")
		presenter.Err(w, r, err, "explain failed")
		return
	}

	presenter.JSON(w, r, trace, http.StatusOK)
}
