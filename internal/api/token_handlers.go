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

	resp, err := s.current().IssueLease(ctx, service.IssueRequest{
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

	resp, err := s.current().RevokeLease(ctx, service.RevokeRequest{
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
