package client

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/darmiel/talmi/internal/api"
)

func TestProviders(t *testing.T) {
	t.Parallel()
	is := assert.New(t)
	must := require.New(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		is.Equal(api.ProvidersRoute, r.URL.Path)
		is.Equal(http.MethodGet, r.Method)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"name":"gh-ro","realm":"ghes-corp","type":"github-app","mode":"api","resources":["ghes-corp:acme/*"],"max_actions":["contents:read"]}]`))
	}))
	defer srv.Close()

	c := New(srv.URL)
	infos, _, err := c.Providers(context.Background())
	must.NoError(err)
	must.Len(infos, 1)
	is.Equal("gh-ro", infos[0].Name)
	is.Equal("api", infos[0].Mode)
	is.Equal([]string{"contents:read"}, infos[0].MaxActions)
}

func TestResolve(t *testing.T) {
	t.Parallel()
	is := assert.New(t)
	must := require.New(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		is.Equal(api.ResolveRoute, r.URL.Path)
		is.Equal(http.MethodPost, r.Method)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"resource":"ghes-corp:acme/x","actions":["contents:read"],"realm":"ghes-corp","chosen":"gh-ro","candidates":[{"provider":"gh-ro","covered":true}]}]`))
	}))
	defer srv.Close()

	c := New(srv.URL)
	res, _, err := c.Resolve(context.Background(), []ResourceRequest{
		{Resource: "ghes-corp:acme/x", Actions: []string{"contents:read"}},
	})
	must.NoError(err)
	must.Len(res, 1)
	is.Equal("gh-ro", res[0].Chosen)
	must.Len(res[0].Candidates, 1)
	is.True(res[0].Candidates[0].Covered)
}
