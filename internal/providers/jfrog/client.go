package jfrog

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/darmiel/talmi/internal/api/middleware"
	"github.com/darmiel/talmi/internal/audit"
)

const createTokenEndpoint = "/access/api/v1/tokens"

// CreateTokenRequest represents the request body for creating an access token in JFrog Artifactory.
// info from: https://jfrog.com/help/r/jfrog-rest-apis/recommended-configurations
type CreateTokenRequest struct {
	// The grant type used to authenticate the request.
	// optional, default: client_credentials
	GrantType string `json:"grant_type,omitempty"`

	// The Username for which this token is created.
	// The Username is based on the authenticated user - either from the user of the authenticated token or
	// based on the username (if basic auth was used).
	// The username is then used to set the subject of the token: <service-id>/users/<username>
	// optional, default: (token holder)
	Username string `json:"username,omitempty"`

	// The scope of access that the token provides.
	// optional, default: "applied-permissions/user" (token holder)
	Scope string `json:"scope,omitempty"`

	// The amount of time, in seconds, it would take for the token to expire.
	// optional: default: 1 year
	ExpiresIn int64 `json:"expires_in"`

	// optional, default: false
	Refreshable bool `json:"refreshable"`

	// Free text token description.
	// optional, default: ""
	Description string `json:"description,omitempty"`

	// A space-separated list of the other instances or services that
	// should accept this token identified by their Service-IDs.
	// optional, default: ""
	Audience string `json:"audience,omitempty"`

	// Generate a Reference Token (alias to Access Token) in addition to the full token.
	// optional, default: false
	IncludeReferenceToken bool `json:"include_reference_token"`
}

type CreateTokenResponse struct {
	TokenID     string `json:"token_id"`
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope"`
	TokenType   string `json:"token_type"`
	Username    string `json:"username"`
}

// CreateToken creates a new access token in JFrog Artifactory based on the provided payload.
func (g *Provider) CreateToken(
	ctx context.Context,
	principalID string,
	payload *CreateTokenRequest,
) (*CreateTokenResponse, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshalling payload: %w", err)
	}
	body := bytes.NewReader(data)

	url := g.serverBaseURL + createTokenEndpoint
	req, err := http.NewRequestWithContext(ctx, "POST", url, body)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+g.token)

	// inject audit user-agent
	correlationID := middleware.CorrelationCtx(ctx)
	req.Header.Set("User-Agent", audit.CreateUserAgent(correlationID, principalID, g.Name()))

	resp, err := g.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("performing request: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var tokenResp CreateTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}
	return &tokenResp, nil
}
