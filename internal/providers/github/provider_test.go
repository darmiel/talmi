package github

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/go-github/v80/github"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/darmiel/talmi/internal/core"
)

func fakeDiscover(d *discovered, calls *int) func(ctx context.Context) (*discovered, error) {
	return func(ctx context.Context) (*discovered, error) {
		*calls++
		return d, nil
	}
}

func newTestProvider(t *testing.T, d *discovered) (*Provider, *int) {
	t.Helper()
	p, err := New("gh-corp", "ghes-corp", ProviderConfig{
		PrivateKey: []byte("test-key"),
		AppID:      1,
	})
	require.NoError(t, err)
	calls := 0
	p.discover = fakeDiscover(d, &calls)
	return p, &calls
}

func TestNewDefaults(t *testing.T) {
	t.Parallel()
	is := assert.New(t)

	p, err := New("gh-corp", "ghes-corp", ProviderConfig{
		PrivateKey: []byte("k"),
		AppID:      1,
	})
	is.NoError(err)
	is.NotNil(p.discover, "New must wire a default discover function")
	is.Positive(p.capTTL, "New must set a default capability TTL")
}

func TestSplitOwnerRepo(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		resource  core.Resource
		wantOwner string
		wantRepo  string
		wantOK    bool
	}{
		{"owner and repo", "ghes-corp:acme/service-a", "acme", "service-a", true},
		{"no realm colon", "acme/service-a", "acme", "service-a", true}, // Body() returns whole string
		{"missing slash", "ghes-corp:acme", "", "", false},
		{"leading slash", "ghes-corp:/repo", "", "", false},
		{"trailing slash", "ghes-corp:acme/", "", "", false},
		{"empty", "", "", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			is := assert.New(t)

			owner, repo, ok := splitOwnerRepo(tt.resource)
			is.Equal(tt.wantOK, ok)
			if ok {
				is.Equal(tt.wantOwner, owner)
				is.Equal(tt.wantRepo, repo)
			}
		})
	}
}

func TestReposIn(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		group []core.ResourceRequest
		want  []string
	}{
		{
			name: "dedups and sorts",
			group: []core.ResourceRequest{
				{Resource: "ghes-corp:acme/svc-b"},
				{Resource: "ghes-corp:acme/svc-a"},
				{Resource: "ghes-corp:acme/svc-b"}, // duplicate
			},
			want: []string{"svc-a", "svc-b"},
		},
		{
			name:  "skips malformed resources",
			group: []core.ResourceRequest{{Resource: "ghes-corp:acme"}, {Resource: "ghes-corp:acme/ok"}},
			want:  []string{"ok"},
		},
		{
			name:  "empty group yields nothing",
			group: nil,
			want:  nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, reposIn(tt.group))
		})
	}
}

func TestUnionPerms(t *testing.T) {
	t.Parallel()

	req := func(actions ...core.Action) core.ResourceRequest {
		return core.ResourceRequest{Actions: actions}
	}
	tests := []struct {
		name  string
		group []core.ResourceRequest
		want  map[string]string
	}{
		{
			name:  "single action",
			group: []core.ResourceRequest{req("contents:read")},
			want:  map[string]string{"contents": "read"},
		},
		{
			name:  "multiple distinct permissions",
			group: []core.ResourceRequest{req("contents:read", "actions:write")},
			want:  map[string]string{"contents": "read", "actions": "write"},
		},
		{
			name:  "keeps higher level regardless of order (read then write)",
			group: []core.ResourceRequest{req("contents:read"), req("contents:write")},
			want:  map[string]string{"contents": "write"},
		},
		{
			name:  "keeps higher level regardless of order (write then read)",
			group: []core.ResourceRequest{req("contents:write"), req("contents:read")},
			want:  map[string]string{"contents": "write"},
		},
		{
			name:  "admin beats write",
			group: []core.ResourceRequest{req("contents:write"), req("contents:admin")},
			want:  map[string]string{"contents": "admin"},
		},
		{
			name:  "duplicate identical actions collapse",
			group: []core.ResourceRequest{req("contents:read"), req("contents:read")},
			want:  map[string]string{"contents": "read"},
		},
		{
			name:  "action without colon is skipped",
			group: []core.ResourceRequest{req("contents")},
			want:  map[string]string{},
		},
		{
			name:  "unknown level is dropped (fail-safe)",
			group: []core.ResourceRequest{req("contents:bogus")},
			want:  map[string]string{},
		},
		{
			name:  "known level survives alongside unknown",
			group: []core.ResourceRequest{req("contents:read", "contents:bogus")},
			want:  map[string]string{"contents": "read"},
		},
		{
			name:  "empty group",
			group: nil,
			want:  map[string]string{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, unionPerms(tt.group))
		})
	}
}

func TestPermsToActions(t *testing.T) {
	t.Parallel()

	t.Run("nil permissions", func(t *testing.T) {
		t.Parallel()
		is := assert.New(t)

		actions, err := permsToActions(nil)
		is.NoError(err)
		is.Nil(actions)
	})

	t.Run("only set fields become actions", func(t *testing.T) {
		t.Parallel()
		is := assert.New(t)

		var perms github.InstallationPermissions
		require.NoError(t, json.Unmarshal([]byte(`{"contents":"write","metadata":"read"}`), &perms))

		actions, err := permsToActions(&perms)
		is.NoError(err)
		is.ElementsMatch([]core.Action{"contents:write", "metadata:read"}, actions)
	})
}

func TestCapabilities(t *testing.T) {
	t.Parallel()
	is := assert.New(t)

	p, _ := newTestProvider(t, &discovered{
		appActions:   []core.Action{"contents:write", "metadata:read"},
		reposByOwner: map[string][]string{"acme": {"a", "b"}, "beta": {"c"}},
	})

	capabilities, err := p.Capabilities(context.Background())
	is.NoError(err)
	is.Equal("ghes-corp", capabilities.Realm)
	is.ElementsMatch([]string{"ghes-corp:acme/a", "ghes-corp:acme/b", "ghes-corp:beta/c"}, capabilities.Resources)
	is.ElementsMatch([]core.Action{"contents:write", "metadata:read"}, capabilities.MaxActions)
}

func TestCapabilitiesCaching(t *testing.T) {
	t.Parallel()
	is := assert.New(t)

	p, calls := newTestProvider(t, &discovered{reposByOwner: map[string][]string{"acme": {"a"}}})

	_, err := p.Capabilities(context.Background())
	is.NoError(err)
	_, err = p.Capabilities(context.Background())
	is.NoError(err)
	is.Equal(1, *calls, "second call within TTL must hit the cache")

	p.Invalidate()
	_, err = p.Capabilities(context.Background())
	is.NoError(err)
	is.Equal(2, *calls, "after Invalidate, next call must refresh the cache")
}

func TestPlanGroupsByOwner(t *testing.T) {
	t.Parallel()
	is := assert.New(t)

	p, _ := newTestProvider(t, &discovered{
		installByOwner: map[string]int64{"acme": 111, "beta": 222},
		reposByOwner:   map[string][]string{"acme": {"a", "b"}, "beta": {"c"}},
	})

	plans, err := p.Plan(context.Background(), []core.ResourceRequest{
		{Resource: "ghes-corp:acme/a", Actions: []core.Action{"contents:read"}},
		{Resource: "ghes-corp:acme/b", Actions: []core.Action{"contents:write"}},
		{Resource: "ghes-corp:beta/c", Actions: []core.Action{"metadata:read"}},
	})
	is.NoError(err)
	is.Len(plans, 2, "must produce one plan per owner")

	byInstall := make(map[int64]ghMintPlan)
	for _, pl := range plans {
		is.Equal("gh-corp", pl.Provider)
		is.Equal("ghes-corp", pl.Realm)

		mp, ok := pl.Internal.(ghMintPlan)
		is.True(ok, "Internal must be ghMintPlan")
		byInstall[mp.installationID] = mp
	}

	is.ElementsMatch([]string{"a", "b"}, byInstall[111].repos)
	is.Equal("write", byInstall[111].perms["contents"], "union kept the higher level")
	is.Equal([]string{"c"}, byInstall[222].repos)
	is.Equal("read", byInstall[222].perms["metadata"])
}

func TestPlanErrors(t *testing.T) {
	t.Parallel()

	t.Run("malformed resource", func(t *testing.T) {
		t.Parallel()
		is := assert.New(t)

		p, _ := newTestProvider(t, &discovered{installByOwner: map[string]int64{"acme": 1}})
		_, err := p.Plan(context.Background(), []core.ResourceRequest{{Resource: "ghes-corp:acme"}}) // missing repo
		is.Error(err)
		is.Contains(err.Error(), "malformed")
	})

	t.Run("owner without installation", func(t *testing.T) {
		t.Parallel()
		is := assert.New(t)

		p, _ := newTestProvider(t, &discovered{installByOwner: map[string]int64{"acme": 1}})
		_, err := p.Plan(context.Background(), []core.ResourceRequest{{Resource: "ghes-corp:beta/c"}}) // beta has no installation
		is.Error(err)
		is.Contains(err.Error(), "no installation found")
	})
}

func TestRevokeIsIdempotentOnAlreadyRevoked(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		status  int
		wantErr bool
	}{
		{"401 unauthorized (token already invalid)", http.StatusUnauthorized, false},
		{"404 not found", http.StatusNotFound, false},
		{"500 server error still fails", http.StatusInternalServerError, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
			}))
			defer ts.Close()

			p, _ := newTestProvider(t, &discovered{})
			p.serverBaseURL = ts.URL

			err := p.Revoke(context.Background(), "github-installation-1", "dead-token")
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err, "an already-gone token must make revoke a no-op success")
			}
		})
	}
}

func TestNewRefreshIntervalSetsCapTTL(t *testing.T) {
	t.Parallel()
	is := assert.New(t)

	custom, err := New("gh", "ghes-corp", ProviderConfig{
		PrivateKey: []byte("k"), AppID: 1, RefreshInterval: 2 * time.Minute,
	})
	require.NoError(t, err)
	is.Equal(2*time.Minute, custom.capTTL, "configured refresh_interval must set capTTL")

	def, err := New("gh", "ghes-corp", ProviderConfig{PrivateKey: []byte("k"), AppID: 1})
	require.NoError(t, err)
	is.Equal(15*time.Minute, def.capTTL, "unset refresh_interval falls back to the default")
}
