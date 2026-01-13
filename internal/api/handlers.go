package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/darmiel/talmi/internal/api/presenter"
	"github.com/darmiel/talmi/internal/buildinfo"
	"github.com/darmiel/talmi/internal/core"
	"github.com/darmiel/talmi/internal/engine"
)

// handleHealth responds with a simple OK status to indicate the server is healthy.
func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("OK"))
}

// handleAbout responds with service information including version and commit hash.
func (s *Server) handleAbout(w http.ResponseWriter, r *http.Request) {
	presenter.JSON(w, r, buildinfo.GetBuildInfo(), http.StatusOK)
}

type IssuePayload struct {
	// Permissions specifies requested permissions for the issued token.
	Permissions map[string]string `json:"permissions"`

	// Issuer specifies the desired issuer to verify the token against.
	// It skips issuer auto-discovery.
	Issuer string

	// Provider specifies the desired provider to issue the token from.
	Provider string
}

func DecodePayload(r *http.Request, dest any, allowEmpty bool) error {
	switch r.Header.Get("Content-Type") {
	case "application/json", "":
		// strict encoding for JSON
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		if err := dec.Decode(dest); err != nil {
			if !errors.Is(err, io.EOF) || !allowEmpty {
				return err
			}
		}
		// ensure there's no extra data
		if dec.More() {
			return errors.New("extra data in request body")
		}
		return nil
	default:
		return errors.New("unsupported content type")
	}
}

// handleIssue processes token issuance requests.
func (s *Server) handleIssue(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := log.Ctx(ctx)
	reqID, _ := ctx.Value("correlation_id").(string)

	auditEntry := core.AuditEntry{
		ID:     reqID,
		Time:   time.Now(),
		Action: "issue_token",
	}
	defer func() {
		if err := s.auditor.Log(auditEntry); err != nil {
			logger.Error().Err(err).Msg("failed to write audit log")
		}
	}()

	// parse request payload
	var payload IssuePayload
	if err := DecodePayload(r, &payload, true /* allow empty */); err != nil {
		logger.Warn().Err(err).Msg("failed to decode issue request payload")
		presenter.Error(w, r, "invalid request payload", http.StatusBadRequest)
		auditEntry.Error = "invalid request payload"
		return
	}

	// read token from Authorization header
	authHeader := r.Header.Get("Authorization")
	token := strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer"))
	if token == "" {
		logger.Warn().Msgf("missing or empty Authorization header")
		presenter.Error(w, r, "missing Authorization header", http.StatusUnauthorized)
		auditEntry.Error = "missing Authorization header"
		return
	}

	auditEntry.RequestedIssuer = payload.Issuer
	auditEntry.RequestedProvider = payload.Provider

	var issuer core.Issuer
	if payload.Issuer != "" { // TODO(future): check if we should allow this in the future, if there's an issuer that accepts too many token types a user might be able to abuse that
		// the user specified a specific issuer
		iss, ok := s.issuers.Get(payload.Issuer)
		if !ok {
			logger.Warn().Str("requested_issuer", payload.Issuer).Msgf("requested issuer not found")
			presenter.Error(w, r, "requested issuer not found", http.StatusBadRequest)
			auditEntry.Error = "requested issuer not found"
			return
		}
		issuer = iss
		logger.Debug().Str("issuer", issuer.Name()).Msg("using explicit issuer")
	} else {
		iss, err := s.issuers.IdentifyIssuer(token)
		if err != nil {
			logger.Warn().Err(err).Msgf("issuer auto-discovery failed")
			presenter.Error(w, r, "could not identify issuer from token", http.StatusBadRequest)
			auditEntry.Error = "issuer auto-discovery failed"
			return
		}
		issuer = iss
		logger.Debug().Str("issuer", issuer.Name()).Msg("using discovered issuer")
	}

	principal, err := issuer.Verify(ctx, token)
	if err != nil {
		logger.Warn().Err(err).Str("issuer", issuer.Name()).Msgf("upstream token verification failed")
		presenter.Error(w, r, "token verification failed", http.StatusUnauthorized)
		auditEntry.Error = "upstream token verification failed"
		return
	}
	auditEntry.Principal = principal

	logger.UpdateContext(func(c zerolog.Context) zerolog.Context {
		return c.Str("sub", principal.ID)
	})

	// evaluate policies
	rule, err := s.engine.Evaluate(principal, payload.Provider) // TODO(future): here as well, check if we should allow filtering by provider
	if err != nil {
		auditEntry.Granted = false

		if errors.Is(err, engine.ErrNoRuleMatch) {
			logger.Warn().Msg("policy denied")
			presenter.Error(w, r, "access denied: no matching policy rule", http.StatusForbidden)
			auditEntry.Error = "access denied: no matching policy rule"
			return
		}
		logger.Error().Err(err).Msgf("policy engine error")
		presenter.Error(w, r, "internal policy error", http.StatusInternalServerError)
		auditEntry.Error = "internal policy error"
		return
	}
	auditEntry.PolicyName = rule.Name

	// find provider
	grant := rule.Grant
	provider, ok := s.providers[grant.Provider]
	if !ok {
		logger.Error().Str("grant_provider", grant.Provider).Msg("grant references unknown provider")
		presenter.Error(w, r, "misconfiguration: provider not found", http.StatusInternalServerError)
		auditEntry.Error = "misconfiguration: provider not found"
		return
	}
	auditEntry.Provider = provider.Name()

	// downscope permissions
	effectivePermissions, err := provider.Downscope(grant.Permissions, payload.Permissions)
	if err != nil {
		logger.Error().Err(err).Msg("failed to downscope permissions")
		presenter.Error(w, r, "failed to downscope permissions: "+err.Error(), http.StatusInternalServerError)
		auditEntry.Error = "failed to downscope permissions"
		return
	}

	effectiveGrant := grant
	effectiveGrant.Permissions = effectivePermissions

	// mint token
	artifact, err := provider.Mint(ctx, principal, effectiveGrant)
	if err != nil {
		logger.Error().Err(err).Str("provider", provider.Name()).Msg("minting failed")
		presenter.Error(w, r, "token minting failed", http.StatusInternalServerError)
		auditEntry.Error = "token minting failed"
		return
	}
	auditEntry.Granted = true
	auditEntry.Metadata = artifact.Metadata
	auditEntry.TokenFingerprint = artifact.Fingerprint

	meta := core.TokenMetadata{
		CorrelationID: reqID,
		PrincipalID:   principal.ID,
		Provider:      provider.Name(),
		PolicyName:    rule.Name,
		ExpiresAt:     artifact.ExpiresAt,
		IssuedAt:      time.Now(),
		Metadata:      artifact.Metadata,
	}
	if err := s.tokenStore.Save(ctx, meta); err != nil {
		logger.Error().Err(err).Msg("failed to store token metadata")
	}

	logger.Info().
		Str("provider", provider.Name()).
		Msg("token issued successfully")

	presenter.JSON(w, r, artifact, http.StatusCreated)
}

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

	trace := s.engine.Trace(principal, requestedProvider)
	trace.CorrelationID = reqID

	presenter.JSON(w, r, trace, http.StatusOK)
}
