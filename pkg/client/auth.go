package client

import (
	"context"
	"net/http"
	"time"

	"github.com/darmiel/talmi/internal/api"
)

// LoginInfo mirrors the server's public /v2/auth/config.
type LoginInfo struct {
	Server   string   `json:"server"`
	ClientID string   `json:"client_id"`
	Scopes   []string `json:"scopes"`
}

// SessionResponse is returned by /v2/auth/session.
type SessionResponse struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

// GetLoginInfo fetches the device-flow parameters
func (c *Client) GetLoginInfo(ctx context.Context) (*LoginInfo, string, error) {
	var info LoginInfo
	correlation, err := c.get(ctx, c.url(api.LoginConfigRoute).build(), &info)
	return &info, correlation, err
}

// ExchangeSession trades a GHES OAuth access token for a Talmi session JWT.
func (c *Client) ExchangeSession(ctx context.Context, ghesToken string) (*SessionResponse, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url(api.LoginRoute).build(), nil)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("Authorization", "Bearer "+ghesToken)
	var session SessionResponse
	correlation, err := c.do(req, &session)
	return &session, correlation, err
}
