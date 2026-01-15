package api

import (
	"net/http"
	"strconv"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/darmiel/talmi/internal/api/presenter"
	"github.com/darmiel/talmi/internal/core"
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

// handleExplain processes token explanation requests.
func (s *Server) handleExplain(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := log.Ctx(ctx)
	reqID, _ := ctx.Value("correlation_id").(string)

	// read token from body
	token := r.FormValue("token")

	// optional requested issuer / provider
	q := r.URL.Query()
	requestedIssuer := q.Get("issuer")
	requestedProvider := q.Get("provider")
	replayID := q.Get("replay_id")

	var principal *core.Principal

	if replayID != "" {
		logger.UpdateContext(func(c zerolog.Context) zerolog.Context {
			return c.Str("replay_id", replayID)
		})

		// fetch the audit entry to replay
		entries, err := s.auditor.Find(func(entry core.AuditEntry) bool {
			return entry.ID == replayID
		}, 1)
		if err != nil {
			logger.Error().Err(err).Msg("failed to retrieve audit log for replay")
			presenter.Error(w, r, "failed to retrieve audit log for replay", http.StatusInternalServerError)
			return
		}

		principal = entries[0].Principal
		if principal == nil {
			logger.Warn().Msg("no principal found in audit log for replay")
			presenter.Error(w, r, "no principal found in audit log for replay", http.StatusBadRequest)
			return
		}

		logger.Debug().Str("sub", principal.ID).Msg("replaying audit log entry")
	} else {
		// normal token validation flow to get principal
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
			iss, err := s.issuers.IdentifyIssuer(token)
			if err != nil {
				logger.Warn().Err(err).Msgf("issuer auto-discovery failed")
				presenter.Error(w, r, "could not identify issuer from token", http.StatusBadRequest)
				return
			}
			issuer = iss
			logger.Debug().Str("issuer", issuer.Name()).Msg("using discovered issuer")
		}

		var err error
		principal, err = issuer.Verify(ctx, token)
		if err != nil {
			logger.Warn().Err(err).Str("issuer", issuer.Name()).Msgf("upstream token verification failed")
			presenter.Error(w, r, "token verification failed", http.StatusUnauthorized)
			return
		}
	}

	logger.UpdateContext(func(c zerolog.Context) zerolog.Context {
		return c.Str("sub", principal.ID)
	})

	trace := s.policyManager.GetEngine().Trace(principal, requestedProvider)
	trace.CorrelationID = reqID

	presenter.JSON(w, r, trace, http.StatusOK)
}
