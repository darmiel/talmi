package client

import (
	"context"

	"github.com/darmiel/talmi/internal/api"
	"github.com/darmiel/talmi/internal/resolver"
)

type resolveRequestBody struct {
	Resources []ResourceRequest `json:"resources"`
}

func (c *Client) Resolve(
	ctx context.Context,
	requests []ResourceRequest,
) ([]resolver.RequestResolution, string, error) {
	var out []resolver.RequestResolution
	correlationID, err := c.post(ctx, c.url(api.ResolveRoute).build(), resolveRequestBody{
		Resources: requests,
	}, &out)
	return out, correlationID, err
}
