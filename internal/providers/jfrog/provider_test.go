package jfrog

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/darmiel/talmi/internal/core"
)

func TestGroupScope(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		groups []string
		want   string
	}{
		{"single", []string{"docker-readers"}, `applied-permissions/groups:"docker-readers"`},
		{"multiple", []string{"a", "b"}, `applied-permissions/groups:"a","b"`},
		{"space in name", []string{"team writers"}, `applied-permissions/groups:"team writers"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, groupScope(tt.groups))
		})
	}
}

func TestNewValidation(t *testing.T) {
	t.Parallel()
	base := ProviderConfig{Server: "https://art", Token: "tok", Groups: []string{"g"}}

	t.Run("valid", func(t *testing.T) {
		t.Parallel()
		p, err := New("art", "artifactory", base)
		require.NoError(t, err)
		assert.Equal(t, time.Hour, p.defaultTTL) // default applied
	})
	t.Run("missing server", func(t *testing.T) {
		t.Parallel()
		cfg := base
		cfg.Server = ""
		_, err := New("art", "artifactory", cfg)
		assert.Error(t, err)
	})
	t.Run("missing token", func(t *testing.T) {
		t.Parallel()
		cfg := base
		cfg.Token = ""
		_, err := New("art", "artifactory", cfg)
		assert.Error(t, err)
	})
	t.Run("missing groups", func(t *testing.T) {
		t.Parallel()
		cfg := base
		cfg.Groups = nil
		_, err := New("art", "artifactory", cfg)
		assert.Error(t, err)
	})
}

func TestPlanAndCapabilities(t *testing.T) {
	t.Parallel()
	is := assert.New(t)

	p, err := New("art-ro", "artifactory", ProviderConfig{
		Server: "https://art", Token: "tok", Groups: []string{"readers"},
		Resources: []string{"artifactory:docker-*"}, MaxActions: []core.Action{"read"},
	})
	require.NoError(t, err)

	capabilities, err := p.Capabilities(t.Context())
	is.NoError(err)
	is.Equal([]string{"artifactory:docker-*"}, capabilities.Resources)
	is.Equal([]core.Action{"read"}, capabilities.MaxActions)

	reqs := []core.ResourceRequest{
		{Resource: "artifactory:docker-prod", Actions: []core.Action{"read"}},
		{Resource: "artifactory:docker-dev", Actions: []core.Action{"read"}},
	}
	plans, err := p.Plan(t.Context(), reqs)
	is.NoError(err)
	is.Len(plans, 1)
	is.Equal(reqs, plans[0].Covers)
}
