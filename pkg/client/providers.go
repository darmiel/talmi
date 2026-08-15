package client

import (
	"context"

	"github.com/darmiel/talmi/internal/api"
)

type ProviderInfo struct {
	Name       string   `json:"name"`
	Realm      string   `json:"realm"`
	Type       string   `json:"type"`
	Mode       string   `json:"mode"`
	Resources  []string `json:"resources,omitempty"`
	MaxActions []string `json:"max_actions,omitempty"`
	Error      string   `json:"error,omitempty"`
}

func (c *Client) Providers(ctx context.Context) ([]ProviderInfo, string, error) {
	var out []ProviderInfo
	correlationID, err := c.get(ctx, c.url().setPath(api.ProvidersRoute).build(), &out)
	return out, correlationID, err
}
