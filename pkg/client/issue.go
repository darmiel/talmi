package client

import (
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
}

// IssueToken requests a new token from the server using the provided token for authorization.
func (c *Client) IssueToken(ctx context.Context, token string, opts IssueTokenOptions) (*core.TokenArtifact, error) {
	// we do this request manually, because we need to overwrite the authorization header which is used
	// for policy matching. our helper methods cannot do that currently.
	req, err := http.NewRequestWithContext(ctx, "POST", c.url().
		setPath(api.IssueTokenRoute).
		addQueryParamNotEmpty("issuer", opts.RequestedIssuer).
		addQueryParamNotEmpty("provider", opts.RequestedProvider).
		build(), nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("connection failed: %w", err)
	}
	defer func(body io.ReadCloser) {
		_ = body.Close()
	}(resp.Body)

	if resp.StatusCode >= 400 {
		return nil, parseErrorResponse(resp)
	}

	var result core.TokenArtifact
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	return &result, nil
}
