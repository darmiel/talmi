package client

import (
	"context"

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
