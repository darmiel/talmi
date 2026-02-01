package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/darmiel/talmi/internal/api"
	"github.com/darmiel/talmi/internal/core"
)

type ListAuditsOpts struct {
	Limit uint

	CorrelationID string
	PrincipalID   string
	Fingerprint   string
}

// ListAudits retrieves the latest audit entries from the server, limited to the specified number.
func (c *Client) ListAudits(ctx context.Context, opts ListAuditsOpts) ([]core.AuditEntry, string, error) {
	ub := c.url().setPath(api.ListAuditsRoute)
	if opts.Limit > 0 {
		ub = ub.addQueryParam("limit", opts.Limit)
	}
	if opts.CorrelationID != "" {
		ub = ub.addQueryParam("correlation_id", opts.CorrelationID)
	}
	if opts.PrincipalID != "" {
		ub = ub.addQueryParam("principal_id", opts.PrincipalID)
	}
	if opts.Fingerprint != "" {
		ub = ub.addQueryParam("fingerprint", opts.Fingerprint)
	}
	var resp []core.AuditEntry
	correlation, err := c.get(ctx, ub.build(), &resp)
	return resp, correlation, err
}

// ListActiveTokens retrieves the list of currently active tokens from the server.
func (c *Client) ListActiveTokens(ctx context.Context) ([]core.TokenMetadata, string, error) {
	var resp []core.TokenMetadata
	correlation, err := c.get(ctx, c.url().
		setPath(api.ListActiveTokensRoute).
		build(), &resp)
	return resp, correlation, err
}

func (c *Client) ExplainTrace(
	ctx context.Context,
	opts api.ExplainRequest,
) (*core.EvaluationTrace, string, error) {
	marshalled, err := json.Marshal(opts)
	if err != nil {
		return nil, "", err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.url().
		setPath(api.ExplainRoute).
		build(), bytes.NewReader(marshalled))
	if err != nil {
		return nil, "", fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	var trace core.EvaluationTrace
	correlation, err := c.do(req, &trace)
	return &trace, correlation, err
}
