package client

import (
	"bytes"
	"context"
	"net/http"
	"net/url"

	"github.com/darmiel/talmi/internal/api"
	"github.com/darmiel/talmi/internal/core"
)

// ListAudits retrieves the latest audit entries from the server, limited to the specified number.
func (c *Client) ListAudits(ctx context.Context, limit uint) ([]core.AuditEntry, error) {
	var resp []core.AuditEntry
	err := c.get(ctx, c.url().
		setPath(api.ListAuditsRoute).
		addQueryParam("limit", limit).
		build(), &resp)
	return resp, err
}

// ListActiveTokens retrieves the list of currently active tokens from the server.
func (c *Client) ListActiveTokens(ctx context.Context) ([]core.TokenMetadata, error) {
	var resp []core.TokenMetadata
	err := c.get(ctx, c.url().
		setPath(api.ListActiveTokensRoute).
		build(), &resp)
	return resp, err
}

type ExplainTraceOptions struct {
	RequestedIssuer   string
	RequestedProvider string
}

func (c *Client) ExplainTrace(
	ctx context.Context,
	token string,
	opts ExplainTraceOptions,
) (*core.EvaluationTrace, error) {
	formData := url.Values{
		"token": {token},
	}
	body := bytes.NewBufferString(formData.Encode())

	req, err := http.NewRequestWithContext(ctx, "POST", c.url().
		setPath(api.ExplainRoute).
		addQueryParam("issuer", opts.RequestedIssuer).
		addQueryParam("provider", opts.RequestedProvider).
		build(), body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	var trace core.EvaluationTrace
	err = c.do(req, &trace)
	return &trace, err
}
