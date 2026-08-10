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
	RevocationSecret string               `json:"revocation_secret,omitempty"`
	Artifacts        []issuedArtifactBody `json:"artifacts"`
}

type issuedArtifactBody struct {
	ArtifactID                 string         `json:"artifact_id"`
	Provider                   string         `json:"provider"`
	Realm                      string         `json:"realm"`
	Covers                     []string       `json:"covers"`
	Token                      string         `json:"token"`
	Fingerprint                string         `json:"fingerprint,omitempty"`
	ExpiresAt                  time.Time      `json:"expires_at"`
	RequiresTokenForRevocation bool           `json:"requires_token_for_revocation"`
	Metadata                   map[string]any `json:"metadata,omitempty"`
}

type revokeRequestBody struct {
	Tokens map[string]string `json:"tokens,omitempty"` // artifact ID -> token value
}

type revokeResponseBody struct {
	LeaseID string   `json:"lease_id"`
	Revoked []string `json:"revoked"`
}

type explainPrincipal struct {
	ID         string         `json:"ID"`
	Issuer     string         `json:"issuer"`
	Attributes map[string]any `json:"attributes"`
}

type explainResponseBody struct {
	Principal explainPrincipal `json:"principal"`
	Decision  core.Decision    `json:"decision"`
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
	if err := DecodePayload(w, r, &body, false); err != nil {
		logger.Warn().Err(err).Msg("invalid issue payload")
		presenter.Error(w, r, "invalid request payload", http.StatusBadRequest)
		return
	}
	if len(body.Resources) == 0 {
		presenter.Error(w, r, "at least one resource is required", http.StatusBadRequest)
		return
	}
	for _, rr := range body.Resources {
		if len(rr.Actions) == 0 {
			presenter.Error(w, r, "each resource requires at least one action", http.StatusBadRequest)
			return
		}
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
	if err := DecodePayload(w, r, &body, false); err != nil {
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

func (s *Server) handleExplain(w http.ResponseWriter, r *http.Request) {
	token := bearerToken(r)
	if token == "" {
		presenter.Error(w, r, "missing bearer token", http.StatusUnauthorized)
		return
	}
	var body issueRequestBody
	if err := DecodePayload(w, r, &body, false); err != nil {
		presenter.Error(w, r, "invalid request payload", http.StatusBadRequest)
		return
	}
	if len(body.Resources) == 0 {
		presenter.Error(w, r, "at least one resource is required", http.StatusBadRequest)
		return
	}
	for _, rr := range body.Resources {
		if len(rr.Actions) == 0 {
			presenter.Error(w, r, "each resource requires at least one action", http.StatusBadRequest)
			return
		}
	}

	resp, err := s.current().Explain(r.Context(), service.IssueRequest{
		Token:           token,
		RequestedIssuer: body.Issuer,
		Resources:       toResourceRequests(body.Resources),
	})
	if err != nil {
		presenter.Err(w, r, err, "explain failed")
		return
	}

	presenter.JSON(w, r, explainResponseBody{
		Principal: explainPrincipal{
			ID:         resp.Principal.ID,
			Issuer:     resp.Principal.Issuer,
			Attributes: resp.Principal.Attributes,
		},
		Decision: resp.Decision,
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
			ArtifactID:                 a.ArtifactID,
			Provider:                   a.Provider,
			Realm:                      a.Realm,
			Covers:                     covers,
			Token:                      a.Token,
			Fingerprint:                a.Fingerprint,
			ExpiresAt:                  a.ExpiresAt,
			RequiresTokenForRevocation: a.RequiresTokenForRevocation,
			Metadata:                   a.Metadata,
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
