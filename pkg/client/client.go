package client

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Client is a simple HTTP client for interacting with a hosted Talmi instance.
type Client struct {
	baseURL    string
	httpClient *http.Client
	authToken  string
}

func New(baseURL string, options ...Option) *Client {
	// our routes contain slashes at the start, so we trim the base URL suffix slash if present
	if strings.HasSuffix(baseURL, "/") {
		baseURL = strings.TrimSuffix(baseURL, "/")
	}
	client := &Client{
		baseURL: baseURL,
	}
	for _, option := range options {
		option(client)
	}
	if client.httpClient == nil {
		client.httpClient = &http.Client{
			Timeout: 30 * time.Second,
		}
	}
	return client
}

type Option func(*Client)

func WithHTTPClient(httpClient *http.Client) Option {
	return func(c *Client) {
		c.httpClient = httpClient
	}
}

func WithAuthToken(token string) Option {
	return func(c *Client) {
		c.authToken = token
	}
}

type kv struct {
	key   string
	value any
}

type urlBuilder struct {
	baseURL      string
	path         string
	orderedQuery []kv
}

func newURLBuilder(baseURL string) *urlBuilder {
	return &urlBuilder{
		baseURL: baseURL,
	}
}

func (u *urlBuilder) setPath(path string) *urlBuilder {
	u.path = path
	return u
}

func (u *urlBuilder) setPaths(paths ...string) *urlBuilder {
	fragments := make([]string, 0, len(paths))
	for _, p := range paths {
		trimmed := strings.Trim(p, "/")
		if trimmed != "" {
			fragments = append(fragments, trimmed)
		}
	}
	u.path = "/" + strings.Join(fragments, "/")
	return u
}

func (u *urlBuilder) addQueryParam(key string, value any) *urlBuilder {
	u.orderedQuery = append(u.orderedQuery, kv{key: key, value: value})
	return u
}

func (u *urlBuilder) build() string {
	var bob strings.Builder
	bob.WriteString(u.baseURL)
	bob.WriteString(u.path)

	if len(u.orderedQuery) > 0 {
		bob.WriteString("?")
		values := url.Values{}
		for _, kv := range u.orderedQuery {
			values.Set(kv.key, fmt.Sprintf("%v", kv.value))
		}
		bob.WriteString(values.Encode())
	}

	return bob.String()
}

// url constructs a full URL for the given path and query parameters.
func (c *Client) url() *urlBuilder {
	return newURLBuilder(c.baseURL)
}
