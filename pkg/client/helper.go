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

func (c *Client) get(ctx context.Context, url string, result any) error {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}
	return c.do(req, result)
}

func (c *Client) post(ctx context.Context, url string, payload, result any) error {
	var body io.Reader
	if payload != nil {
		bodyBytes, err := json.Marshal(payload)
		if err != nil {
			return fmt.Errorf("marshaling payload: %w", err)
		}
		body = bytes.NewBuffer(bodyBytes)
	}
	req, err := http.NewRequestWithContext(ctx, "POST", url, body)
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
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
		return fmt.Errorf("api error: '%s' (correlation: %s)", errResp.Error, errResp.CorrelationID)
	}
	return fmt.Errorf("api error: *unparsed '%s' (status %d)", string(body), resp.StatusCode)
}

func (c *Client) do(req *http.Request, result any) error {
	// inject auth token if available
	if c.authToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.authToken)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("connection failed: %w", err)
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)

	if resp.StatusCode >= 400 {
		return parseErrorResponse(resp)
	}

	if result != nil {
		if err := json.NewDecoder(resp.Body).Decode(result); err != nil {
			return fmt.Errorf("failed to decode response: %w", err)
		}
	}

	return nil
}
