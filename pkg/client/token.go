package client

import (
	"context"
	"time"

	"github.com/darmiel/talmi/internal/api"
	"github.com/darmiel/talmi/internal/core"
)

type ResourceRequest struct {
	Resource string   `json:"resource"`
	Actions  []string `json:"actions"`
}

type IssueRequestBody struct {
	Issuer    string            `json:"issuer,omitempty"`
	Resources []ResourceRequest `json:"resources"`
}

type IssuedArtifact struct {
	ArtifactID                 string                 `json:"artifact_id"`
	Provider                   string                 `json:"provider"`
	Realm                      string                 `json:"realm"`
	Covers                     []core.ResourceRequest `json:"covers"`
	Token                      string                 `json:"token"`
	Fingerprint                string                 `json:"fingerprint,omitempty"`
	ExpiresAt                  time.Time              `json:"expires_at"`
	RequiresTokenForRevocation bool                   `json:"requires_token_for_revocation"`
	Metadata                   map[string]any         `json:"metadata,omitempty"`
}

type IssueResponse struct {
	LeaseID          string           `json:"lease_id"`
	RevocationSecret string           `json:"revocation_secret,omitempty"`
	Artifacts        []IssuedArtifact `json:"artifacts"`
}

type RevokeResponse struct {
	LeaseID string   `json:"lease_id"`
	Revoked []string `json:"revoked"`
}

type ExplainPrincipal struct {
	ID         string         `json:"id"`
	Issuer     string         `json:"issuer"`
	Attributes map[string]any `json:"attributes"`
}

type ExplainResponse struct {
	Principal ExplainPrincipal `json:"principal"`
	Decision  core.Decision    `json:"decision"`
	Plan      []core.MintPlan  `json:"plan,omitempty"`
	PlanError string           `json:"plan_error,omitempty"`
}

func (c *Client) IssueLease(ctx context.Context, token string, body IssueRequestBody) (*IssueResponse, string, error) {
	return postAs(ctx, c, api.IssueTokenRoute, token, body, new(IssueResponse))
}

type revokeRequestBody struct {
	Tokens map[string]string `json:"tokens,omitempty"`
}

func (c *Client) RevokeLease(
	ctx context.Context,
	secret string,
	tokens map[string]string,
) (*RevokeResponse, string, error) {
	return postAs(ctx, c, api.RevokeTokenRoute, secret, revokeRequestBody{
		Tokens: tokens,
	}, new(RevokeResponse))
}

func (c *Client) Explain(ctx context.Context, token string, body IssueRequestBody) (*ExplainResponse, string, error) {
	return postAs(ctx, c, api.ExplainRoute, token, body, new(ExplainResponse))
}
