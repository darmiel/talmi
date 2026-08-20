package client

import (
	"context"

	"github.com/darmiel/talmi/internal/api"
	"github.com/darmiel/talmi/internal/core"
)

// AuditFilter selects audit events (all fields optional).
type AuditFilter struct {
	ID          string
	RequestID   string
	SessionID   string
	ActorID     string
	Fingerprint string
	Action      string
	Outcome     string
	Since       string // RFC3339
	Until       string // RFC3339
	Limit       int
}

func (c *Client) QueryAudit(ctx context.Context, filter AuditFilter) ([]core.Event, string, error) {
	u := c.url(api.AuditQueryRoute).
		addQueryParamNotEmpty("id", filter.ID).
		addQueryParamNotEmpty("request_id", filter.RequestID).
		addQueryParamNotEmpty("session_id", filter.SessionID).
		addQueryParamNotEmpty("principal_id", filter.ActorID).
		addQueryParamNotEmpty("fingerprint", filter.Fingerprint).
		addQueryParamNotEmpty("action", filter.Action).
		addQueryParamNotEmpty("outcome", filter.Outcome).
		addQueryParamNotEmpty("since", filter.Since).
		addQueryParamNotEmpty("until", filter.Until).
		addQueryParamNotEmpty("limit", filter.Limit).
		build()

	var events []core.Event
	correlationID, err := c.get(ctx, u, &events)
	return events, correlationID, err
}

func (c *Client) InspectAudit(ctx context.Context, id string) (*core.Event, string, error) {
	u := c.url(api.AuditEntryRoute).
		setPathParam("id", id).
		build()
	var event core.Event
	correlationID, err := c.get(ctx, u, &event)
	return &event, correlationID, err
}
