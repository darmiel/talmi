package api

import (
	"net/http"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/darmiel/talmi/internal/api/presenter"
	"github.com/darmiel/talmi/internal/core"
	"github.com/darmiel/talmi/internal/service"
)

type issueRequestBody struct {
	Issuer    string                `json:"issuer,omitempty"`
	Resources []resourceRequestBody `json:"resources"`
}

type resourceRequestBody struct {
	Resource string   `json:"resource"`
	Actions  []string `json:"actions"`
}

type issueResponseBody struct {
	LeaseID          string               `json:"lease_id"`
	RevocationSecret string               `json:"revocationSecret,omitempty"`
	Artifacts        []issuedArtifactBody `json:"artifacts"`
}

type issuedArtifactBody struct {
	Provider    string         `json:"provider"`
	Realm       string         `json:"realm"`
	Covers      []string       `json:"covers"`
	Token       string         `json:"token"`
	Fingerprint string         `json:"fingerprint"`
	ExpiresAt   time.Time      `json:"expiresAt"`
	Metadata    map[string]any `json:"metadata,omitempty"`
}

type revokeRequestBody struct {
	Tokens map[string]string `json:"tokens,omitempty"` // fingerprint -> token value
}

type revokeResponseBody struct {
	LeaseID string   `json:"lease_id"`
	Revoked []string `json:"revoked"`
}

func (s *Server) handleIssue(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := log.Ctx(ctx)

	token := bearerToken(r)
	if token == "" {
		presenter.Error(w, r, "missing bearer token", http.StatusUnauthorized)
		return
	}

	var body issueRequestBody
	if err := DecodePayload(r, &body, false); err != nil {
		logger.Warn().Err(err).Msg("invalid issue payload")
		presenter.Error(w, r, "invalid request payload", http.StatusBadRequest)
		return
	}
	if len(body.Resources) == 0 {
		presenter.Error(w, r, "at least one resource is required", http.StatusBadRequest)
		return
	}

	resp, err := s.tokenService.IssueLease(ctx, service.IssueRequest{
		Token:           token,
		RequestedIssuer: body.Issuer,
		Resources:       toResourceRequests(body.Resources),
	})
	if err != nil {
		presenter.Err(w, r, err, "issuance failed")
		return
	}

	presenter.JSON(w, r, toIssueResponseBody(resp), http.StatusCreated)
}

func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := log.Ctx(ctx)

	secret := bearerToken(r)
	if secret == "" {
		presenter.Error(w, r, "missing revocation secret", http.StatusUnauthorized)
		return
	}

	var body revokeRequestBody
	if err := DecodePayload(r, &body, false); err != nil {
		logger.Warn().Err(err).Msg("invalid revoke payload")
		presenter.Error(w, r, "invalid request payload", http.StatusBadRequest)
		return
	}

	resp, err := s.tokenService.RevokeLease(ctx, service.RevokeRequest{
		RevocationSecret: secret,
		Tokens:           body.Tokens,
	})
	if err != nil {
		presenter.Err(w, r, err, "revocation failed")
		return
	}

	presenter.JSON(w, r, revokeResponseBody{
		LeaseID: resp.LeaseID,
		Revoked: resp.Revoked,
	}, http.StatusOK)
}

func toResourceRequests(in []resourceRequestBody) []core.ResourceRequest {
	out := make([]core.ResourceRequest, len(in))
	for i, rr := range in {
		actions := make([]core.Action, len(rr.Actions))
		for j, a := range rr.Actions {
			actions[j] = core.Action(a)
		}
		out[i] = core.ResourceRequest{
			Resource: core.Resource(rr.Resource),
			Actions:  actions,
		}
	}
	return out
}

func toIssueResponseBody(resp *service.IssueResponse) issueResponseBody {
	body := issueResponseBody{
		LeaseID:          resp.LeaseID,
		RevocationSecret: resp.RevocationSecret,
		Artifacts:        make([]issuedArtifactBody, len(resp.Artifacts)),
	}
	for i, a := range resp.Artifacts {
		covers := make([]string, len(a.Covers))
		for j, c := range a.Covers {
			covers[j] = string(c.Resource)
		}
		body.Artifacts[i] = issuedArtifactBody{
			Provider:    a.Provider,
			Realm:       a.Realm,
			Covers:      covers,
			Token:       a.Token,
			Fingerprint: a.Fingerprint,
			ExpiresAt:   a.ExpiresAt,
			Metadata:    a.Metadata,
		}
	}
	return body
}

func bearerToken(r *http.Request) string {
	h := strings.TrimSpace(r.Header.Get("Authorization"))
	if h == "" {
		return ""
	}
	const prefix = "Bearer "
	if len(h) >= len(prefix) && strings.EqualFold(h[:len(prefix)], prefix) {
		return strings.TrimSpace(h[len(prefix):])
	}
	return h
}

//
//type IssuePayload struct {
//	// Permissions specifies requested permissions for the issued token.
//	Permissions map[string]string `json:"permissions"`
//
//	// Issuer specifies the desired issuer to verify the token against.
//	// It skips issuer auto-discovery.
//	Issuer string
//
//	// Provider specifies the desired provider to issue the token from.
//	Provider string
//}
//
//// handleIssue processes token issuance requests.
//func (s *Server) handleIssue(w http.ResponseWriter, r *http.Request) {
//	ctx := r.Context()
//	logger := log.Ctx(ctx)
//
//	// parse request payload
//	var payload IssuePayload
//	if err := DecodePayload(r, &payload, true /* allow empty */); err != nil {
//		logger.Warn().Err(err).Msg("failed to decode issue request payload")
//		presenter.Error(w, r, "invalid request payload", http.StatusBadRequest)
//		return
//	}
//
//	// read token from Authorization header
//	authHeader := r.Header.Get("Authorization")
//	token := strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer"))
//	if token == "" {
//		logger.Warn().Msgf("missing or empty Authorization header")
//		presenter.Error(w, r, "missing Authorization header", http.StatusUnauthorized)
//		return
//	}
//
//	result, err := s.tokenService.IssueToken(ctx, service.IssueRequest{
//		Token:                token,
//		RequestedIssuer:      payload.Issuer,
//		RequestedProvider:    payload.Provider,
//		RequestedPermissions: payload.Permissions,
//	})
//	if err != nil {
//		logger.Error().Err(err).Msg("token issuance failed")
//		presenter.Err(w, r, err, "token issuance failed")
//		return
//	}
//
//	logger.Info().
//		Str("provider", result.Rule.Grant.Provider).
//		Msg("token issued successfully")
//
//	presenter.JSON(w, r, result.Artifact, http.StatusCreated)
//}
//
//func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request) {
//	ctx := r.Context()
//	logger := log.Ctx(ctx)
//
//	authHeader := r.Header.Get("Authorization")
//	authProof := strings.TrimPrefix(authHeader, "Bearer ")
//
//	// I'm not sure what I think of using a header for retrieving the original token, but I think this is the most
//	// compatibility option, this may change in the future.
//	originalTokenHeader := r.Header.Get("X-Original-Token")
//	originalToken := strings.TrimPrefix(originalTokenHeader, "Bearer ")
//
//	meta, err := s.tokenService.RevokeToken(ctx, originalToken, authProof)
//	if err != nil {
//		logger.Error().Err(err).Msg("revoking token failed")
//		presenter.Err(w, r, err, "revoking token failed")
//		return
//	}
//
//	logger.Info().
//		Str("origin_correlation", meta.CorrelationID).
//		Str("provider", meta.Provider).
//		Msg("token revoked successfully")
//
//	presenter.JSON(w, r, map[string]string{"status": "ok"}, http.StatusOK)
//}
