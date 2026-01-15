package api

import (
	"errors"
	"net/http"
	"strings"

	"github.com/rs/zerolog/log"

	"github.com/darmiel/talmi/internal/api/presenter"
	"github.com/darmiel/talmi/internal/service"
)

type IssuePayload struct {
	// Permissions specifies requested permissions for the issued token.
	Permissions map[string]string `json:"permissions"`

	// Issuer specifies the desired issuer to verify the token against.
	// It skips issuer auto-discovery.
	Issuer string

	// Provider specifies the desired provider to issue the token from.
	Provider string
}

// handleIssue processes token issuance requests.
func (s *Server) handleIssue(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := log.Ctx(ctx)

	// parse request payload
	var payload IssuePayload
	if err := DecodePayload(r, &payload, true /* allow empty */); err != nil {
		logger.Warn().Err(err).Msg("failed to decode issue request payload")
		presenter.Error(w, r, "invalid request payload", http.StatusBadRequest)
		return
	}

	// read token from Authorization header
	authHeader := r.Header.Get("Authorization")
	token := strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer"))
	if token == "" {
		logger.Warn().Msgf("missing or empty Authorization header")
		presenter.Error(w, r, "missing Authorization header", http.StatusUnauthorized)
		return
	}

	result, err := s.tokenService.IssueToken(ctx, service.IssueRequest{
		Token:                token,
		RequestedIssuer:      payload.Issuer,
		RequestedProvider:    payload.Provider,
		RequestedPermissions: payload.Permissions,
	})
	if err != nil {
		logger.Error().Err(err).Msg("token issuance failed")
		status := http.StatusBadRequest // generic default status
		var httpError service.HTTPError
		if errors.As(err, &httpError) {
			status = httpError.StatusCode
		}
		presenter.Error(w, r, "token issuance failed: "+err.Error(), status)
		return
	}

	logger.Info().
		Str("provider", result.Rule.Grant.Provider).
		Msg("token issued successfully")

	presenter.JSON(w, r, result.Artifact, http.StatusCreated)
}
