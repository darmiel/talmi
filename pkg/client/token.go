package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/darmiel/talmi/internal/api"
	"github.com/darmiel/talmi/internal/core"
)

// IssueTokenOptions contains optional parameters for issuing a token.
type IssueTokenOptions struct {
	// RequestedProvider is an optional provider name to request the token from.
	// If empty, any provider matching the policy will be used.
	// You should only set this in cases where you _know_ the provider to use.
	RequestedProvider string

	// RequestedIssuer is an optional issuer to request the token from.
	// If empty, any issuer matching the policy will be used.
	// You should only set this in cases where you _know_ the issuer to use.
	RequestedIssuer string

	// Permissions can be used to downscope the requested token.
	Permissions map[string]string
}

// IssueToken requests a new token from the server using the provided token for authorization.
func (c *Client) IssueToken(
	ctx context.Context,
	token string,
	opts IssueTokenOptions,
) (*core.TokenArtifact, string, error) {
	// add payload to body (JSON)
	payload := api.IssuePayload{
		Permissions: opts.Permissions,
		Issuer:      opts.RequestedIssuer,
		Provider:    opts.RequestedProvider,
	}
	marshalled, err := json.Marshal(payload)
	if err != nil {
		return nil, "", fmt.Errorf("marshalling payload: %w", err)
	}

	// we do this request manually, because we need to overwrite the authorization header which is used
	// for policy matching. our helper methods cannot do that currently.
	req, err := http.NewRequestWithContext(ctx, "POST", c.url().
		setPath(api.IssueTokenRoute).
		build(), bytes.NewReader(marshalled))
	if err != nil {
		return nil, "", fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, correlationFromResponse(resp), fmt.Errorf("connection failed: %w", err)
	}
	defer func(body io.ReadCloser) {
		_ = body.Close()
	}(resp.Body)

	if resp.StatusCode >= 400 {
		return nil, correlationFromResponse(resp), parseErrorResponse(resp)
	}

	var result core.TokenArtifact
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, correlationFromResponse(resp), fmt.Errorf("decoding response: %w", err)
	}

	return &result, correlationFromResponse(resp), nil
}

func (c *Client) RevokeToken(ctx context.Context, originalToken string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", c.url().
		setPath(api.RevokeTokenRoute).
		build(), nil)
	if err != nil {
		return "", fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("X-Original-Token", "Bearer "+originalToken)
	correlation, err := c.do(req, nil)
	if err != nil {
		return "", fmt.Errorf("revoking token: %w", err)
	}
	return correlation, nil
}

func correlationFromResponse(resp *http.Response) string {
	if resp == nil {
		return ""
	}
	return resp.Header.Get("X-Correlation-ID")
}
