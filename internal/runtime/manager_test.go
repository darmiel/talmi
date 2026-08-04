package runtime

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/darmiel/talmi/internal/config"
	"github.com/darmiel/talmi/internal/core"
	"github.com/darmiel/talmi/internal/service"
)

type fakeSource struct {
	sourced  *config.SourcedConfig
	revision string
	err      error
}

func (f *fakeSource) Load(context.Context) (*config.SourcedConfig, string, error) {
	return f.sourced, f.revision, f.err
}

func devConfig() *config.Config {
	return &config.Config{
		Signing: config.SigningConfig{Algorithm: "HS256", Key: "raw:dev-key"},
		Store:   config.StoreConfig{Type: "memory"},
		Audit:   config.AuditConfig{Enabled: false},
	}
}

func readReq() service.IssueRequest {
	return service.IssueRequest{
		Token: "tok", Resources: []core.ResourceRequest{
			{Resource: "ghes-corp:acme/x", Actions: []core.Action{"contents:read"}},
		},
	}
}

func sourcedWith(resources []string) *config.SourcedConfig {
	return &config.SourcedConfig{
		Issuers: []config.IssuerBlock{
			{
				Name:   "ci",
				Type:   "static",
				Config: map[string]any{"token_map": map[string]any{"tok": map[string]any{"sub": "u"}}},
			},
		},
		Realms: []config.RealmBlock{
			{
				Realm: "ghes-corp", Type: "github-app",
				Capability: config.CapabilityBlock{
					Resources:  []string{"ghes-corp:*/*"},
					MaxActions: []core.Action{"contents:read", "contents:write"},
				},
				Instances: []config.InstanceBlock{{Name: "gh-dev"}},
			},
		},
		Rules: []core.Rule{
			{
				Name: "r", Match: core.Match{Issuer: "ci", AllowEmptyCondition: true},
				Allow: []core.Allow{{Resources: resources, Actions: []core.Action{"contents:read"}}},
			},
		},
	}
}

func TestManagerInitialAndCurrent(t *testing.T) {
	t.Parallel()
	src := &fakeSource{sourced: sourcedWith([]string{"ghes-corp:acme/*"}), revision: "r1"}
	mgr, err := NewManager(context.Background(), devConfig(), src, true)
	require.NoError(t, err)
	defer func(mgr *Manager) {
		_ = mgr.Close()
	}(mgr)

	_, err = mgr.Current().Service.IssueLease(context.Background(), readReq())
	assert.NoError(t, err)
	assert.Equal(t, "r1", mgr.Current().Revision)
}

func TestManagerReloadSwapsBehavior(t *testing.T) {
	t.Parallel()
	src := &fakeSource{sourced: sourcedWith([]string{"ghes-corp:acme/*"}), revision: "r1"}
	mgr, err := NewManager(context.Background(), devConfig(), src, true)
	require.NoError(t, err)
	defer func(mgr *Manager) {
		_ = mgr.Close()
	}(mgr)

	// point the rule at a different repo namespace; acme/x is no longer covered
	src.sourced = sourcedWith([]string{"ghes-corp:locked/*"})
	src.revision = "r2"
	require.NoError(t, mgr.Reload(context.Background()))
	assert.Equal(t, "r2", mgr.Current().Revision)

	_, err = mgr.Current().Service.IssueLease(context.Background(), readReq())
	assert.Error(t, err, "acme/x no longer covered after reload")
}

func TestManagerReloadSameRevisionIsNoop(t *testing.T) {
	t.Parallel()
	src := &fakeSource{sourced: sourcedWith([]string{"ghes-corp:acme/*"}), revision: "r1"}
	mgr, err := NewManager(context.Background(), devConfig(), src, true)
	require.NoError(t, err)
	defer func(mgr *Manager) {
		_ = mgr.Close()
	}(mgr)

	before := mgr.Current()
	require.NoError(t, mgr.Reload(context.Background()))
	assert.Same(t, before, mgr.Current(), "same revision must not swap the runtime")
}

func TestManagerReloadKeepsCurrentOnFailure(t *testing.T) {
	t.Parallel()
	src := &fakeSource{sourced: sourcedWith([]string{"ghes-corp:acme/*"}), revision: "r1"}
	mgr, err := NewManager(context.Background(), devConfig(), src, true)
	require.NoError(t, err)
	defer func(mgr *Manager) {
		_ = mgr.Close()
	}(mgr)
	before := mgr.Current()

	t.Run("source error", func(t *testing.T) {
		src.err = errors.New("git down")
		src.revision = "r2"
		assert.Error(t, mgr.Reload(context.Background()))
		assert.Same(t, before, mgr.Current())
		src.err = nil
	})

	t.Run("invalid candidate config", func(t *testing.T) {
		bad := sourcedWith([]string{"ghes-corp:acme/*"})
		bad.Rules[0].Allow[0].Resources = []string{"unknown-realm:x"} // validation fails
		src.sourced = bad
		src.revision = "r3"
		assert.Error(t, mgr.Reload(context.Background()))
		assert.Same(t, before, mgr.Current(), "bad candidate must not replace a good runtime")
	})
}
