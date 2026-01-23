package client

import (
	"context"
	"net/http"

	"github.com/darmiel/talmi/internal/api"
	"github.com/darmiel/talmi/internal/buildinfo"
)

func (c *Client) Info(
	ctx context.Context,
) (*buildinfo.Info, string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", c.url().
		setPath(api.AboutRoute).
		build(), nil)
	if err != nil {
		return nil, "", err
	}
	var info buildinfo.Info
	correlation, err := c.do(req, &info)
	return &info, correlation, err
}
