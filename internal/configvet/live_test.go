package configvet

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/darmiel/talmi/internal/config"
	"github.com/darmiel/talmi/internal/core"
	"github.com/darmiel/talmi/internal/providers/stub"
	"github.com/darmiel/talmi/internal/realm"
)

func TestLive(t *testing.T) {
	t.Parallel()

	t.Run("all covered - no live errors", func(t *testing.T) {
		t.Parallel()
		ps := []core.ResourceProvider{
			stub.New("gh", "ghes-corp", stub.WithResources("ghes-corp:acme/*"), stub.WithMaxActions("contents:read")),
		}
		r := Live(context.Background(), LiveInput{Static: baseline(), Providers: ps})
		assert.Nil(t, findByCode(r, "CFG-CAPABILITY"))
		assert.Nil(t, findByCode(r, "CFG-COVERAGE"))
	})

	t.Run("capability failure is reported", func(t *testing.T) {
		t.Parallel()
		ps := []core.ResourceProvider{
			stub.New("gh", "ghes-corp", stub.WithCapabilitiesError(errors.New("401 unauthorized"))),
		}
		r := Live(context.Background(), LiveInput{Static: baseline(), Providers: ps})
		f := findByCode(r, "CFG-CAPABILITY")
		require.NotNil(t, f, "findings: %+v", r.Findings)
		assert.Equal(t, SeverityError, f.Severity)
	})

	t.Run("uncovered realm is reported", func(t *testing.T) {
		t.Parallel()
		// the only provider serves a different realm than the rule needs
		ps := []core.ResourceProvider{
			stub.New("x", "other", stub.WithResources("other:a/b"), stub.WithMaxActions("read")),
		}
		r := Live(context.Background(), LiveInput{Static: baseline(), Providers: ps})
		f := findByCode(r, "CFG-COVERAGE")
		require.NotNil(t, f, "findings: %+v", r.Findings)
		assert.Equal(t, SeverityError, f.Severity)
	})

	t.Run("provider-less realm (talmi) is not flagged as uncovered", func(t *testing.T) {
		t.Parallel()
		cfg := &config.Config{
			Signing: config.SigningConfig{Algorithm: "HS256", Key: "raw:super-secret"},
			Store:   config.StoreConfig{Type: "memory"},
			Audit:   config.AuditConfig{Enabled: false},
		}
		sourced := &config.SourcedConfig{
			Issuers: []config.IssuerBlock{
				{Name: "ci", Type: "static", Config: map[string]any{
					"token_map": map[string]any{"tok": map[string]any{"sub": "svc"}},
				}},
			},
			Realms: []config.RealmBlock{
				{Realm: "talmi", Type: "talmi"}, // provider-less by design
			},
			Rules: []core.Rule{
				{
					Name:  "talmi-admins",
					Match: core.Match{Issuer: "ci", AllowEmptyCondition: true},
					Allow: []core.Allow{{Resources: []string{"talmi:admin/*"}, Actions: []core.Action{"session:mint"}}},
				},
			},
		}
		reg := realm.NewRegistry()
		reg.Register("talmi", realm.Talmi{})
		in := StaticInput{Config: cfg, Sourced: sourced, Realms: reg}

		// No provider serves the talmi realm; it is minted by the session issuer.
		r := Live(context.Background(), LiveInput{Static: in, Providers: nil})
		assert.Nil(t, findByCode(r, "CFG-COVERAGE"),
			"talmi realm must not require a provider; findings: %+v", r.Findings)
	})

	t.Run("Live is a superset of Static", func(t *testing.T) {
		t.Parallel()
		in := baseline()
		in.Sourced.Rules[0].Match.Issuer = "nope" // a static error
		r := Live(context.Background(), LiveInput{
			Static:    in,
			Providers: []core.ResourceProvider{stub.New("gh", "ghes-corp", stub.WithResources("ghes-corp:acme/*"), stub.WithMaxActions("contents:read"))},
		})
		assert.NotNil(t, findByCode(r, "CFG-XREF-ISSUER"), "Live must include Static findings")
	})
}
