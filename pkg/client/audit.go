package client

import (
	"context"

	"github.com/darmiel/talmi/internal/api"
	"github.com/darmiel/talmi/internal/core"
)

// AuditFilter selects audit entries (all fields optional).
type AuditFilter struct {
	CorrelationID string
	PrincipalID   string
	Action        string
	Since         string // RFC3339
	Limit         int
}

func (c *Client) QueryAudit(ctx context.Context, filter AuditFilter) ([]core.AuditEntry, string, error) {
	u := c.url().
		setPath(api.AuditQueryRoute).
		addQueryParamNotEmpty("correlation_id", filter.CorrelationID).
		addQueryParamNotEmpty("principal_id", filter.PrincipalID).
		addQueryParamNotEmpty("action", filter.Action).
		addQueryParamNotEmpty("since", filter.Since).
		addQueryParamNotEmpty("limit", filter.Limit).
		build()

	var entries []core.AuditEntry
	correlationID, err := c.get(ctx, u, &entries)
	return entries, correlationID, err
}
