package api

import (
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
		presenter.Err(w, r, err, "token issuance failed")
		return
	}

	logger.Info().
		Str("provider", result.Rule.Grant.Provider).
		Msg("token issued successfully")

	presenter.JSON(w, r, result.Artifact, http.StatusCreated)
}

func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := log.Ctx(ctx)

	authHeader := r.Header.Get("Authorization")
	authProof := strings.TrimPrefix(authHeader, "Bearer ")

	// I'm not sure what I think of using a header for retrieving the original token, but I think this is the most
	// compatibility option, this may change in the future.
	originalTokenHeader := r.Header.Get("X-Original-Token")
	originalToken := strings.TrimPrefix(originalTokenHeader, "Bearer ")

	meta, err := s.tokenService.RevokeToken(ctx, originalToken, authProof)
	if err != nil {
		logger.Error().Err(err).Msg("revoking token failed")
		presenter.Err(w, r, err, "revoking token failed")
		return
	}

	logger.Info().
		Str("origin_correlation", meta.CorrelationID).
		Str("provider", meta.Provider).
		Msg("token revoked successfully")

	presenter.JSON(w, r, map[string]string{"status": "ok"}, http.StatusOK)
}
