package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/darmiel/talmi/internal/api/presenter"
)

var ErrInvalidSession = fmt.Errorf("invalid session token")

type APIError struct {
	CorrelationID string
	Message       string
}

func (e APIError) Error() string {
	return fmt.Sprintf("api error: '%s' (correlation: %s)", e.Message, e.CorrelationID)
}

func (c *Client) get(ctx context.Context, url string, result any) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", fmt.Errorf("creating request: %w", err)
	}
	return c.do(req, result)
}

func (c *Client) post(ctx context.Context, url string, payload, result any) (string, error) {
	var body io.Reader
	if payload != nil {
		bodyBytes, err := json.Marshal(payload)
		if err != nil {
			return "", fmt.Errorf("marshaling payload: %w", err)
		}
		body = bytes.NewBuffer(bodyBytes)
	}
	req, err := http.NewRequestWithContext(ctx, "POST", url, body)
	if err != nil {
		return "", fmt.Errorf("creating request: %w", err)
	}
	return c.do(req, result)
}

func parseErrorResponse(resp *http.Response) error {
	var errResp presenter.ErrorResponse
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("request failed with status %d and unreadable body: %w", resp.StatusCode, err)
	}
	if json.Unmarshal(body, &errResp) == nil && errResp.Error != "" {
		if errResp.Error == "invalid session token" {
			return ErrInvalidSession
		}
		return APIError{
			CorrelationID: errResp.CorrelationID,
			Message:       errResp.Error,
		}
	}
	return fmt.Errorf("api error: *unparsed '%s' (status %d)", string(body), resp.StatusCode)
}

func (c *Client) do(req *http.Request, result any) (string, error) {
	// inject auth token if available
	if c.authToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.authToken)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("connection failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 400 {
		return correlationFromResponse(resp), parseErrorResponse(resp)
	}

	if result != nil {
		if err := json.NewDecoder(resp.Body).Decode(result); err != nil {
			return correlationFromResponse(resp), fmt.Errorf("failed to decode response: %w", err)
		}
	}

	return correlationFromResponse(resp), nil
}

// postAs POSTs with an explicit bearer (not the client's stored session token)
func postAs[T any](ctx context.Context, c *Client, route, bearer string, body any, out *T) (*T, string, error) {
	data, err := json.Marshal(body)
	if err != nil {
		return nil, "", fmt.Errorf("marshalling payload: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, "POST", c.url().setPath(route).build(), bytes.NewReader(data))
	if err != nil {
		return nil, "", fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+bearer)

	correlation, err := c.do(req, out)
	return out, correlation, err
}

func correlationFromResponse(resp *http.Response) string {
	if resp == nil {
		return ""
	}
	return resp.Header.Get("X-Correlation-ID")
}
