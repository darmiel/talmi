package configvet

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/darmiel/talmi/internal/config"
	"github.com/darmiel/talmi/internal/core"
	"github.com/darmiel/talmi/internal/realm"
)

// baseline returns a fully-valid config with no errors and no warnings.
// Each subtest mutates exactly one thing and asserts the resulting finding.
func baseline() StaticInput {
	cfg := &config.Config{
		Signing: config.SigningConfig{Algorithm: "HS256", Key: "raw:super-secret"},
		Store:   config.StoreConfig{Type: "memory"},
		Audit:   config.AuditConfig{Enabled: false},
	}
	sourced := &config.SourcedConfig{
		Issuers: []config.IssuerBlock{
			{
				Name: "ci", Type: "static", Config: map[string]any{
					"token_map": map[string]any{"tok": map[string]any{"sub": "svc"}},
				},
			},
		},
		Realms: []config.RealmBlock{
			{
				Realm: "ghes-corp", Type: "github-app",
				Capability: config.CapabilityBlock{
					Resources: []string{"ghes-corp:acme/*"}, MaxActions: []core.Action{"contents:read"},
				},
				Instances: []config.InstanceBlock{
					{Name: "gh-1", Config: map[string]any{"app_id": 1, "private_key": "raw:pem"}},
				},
			},
		},
		Rules: []core.Rule{
			{
				Name:  "r",
				Match: core.Match{Issuer: "ci", AllowEmptyCondition: true},
				Allow: []core.Allow{{Resources: []string{"ghes-corp:acme/*"}, Actions: []core.Action{"contents:read"}}},
			},
		},
	}
	reg := realm.NewRegistry()
	reg.Register("ghes-corp", realm.GitHub{})
	return StaticInput{Config: cfg, Sourced: sourced, Realms: reg}
}

// findByCode returns the first finding with the given code, or nil.
func findByCode(r Report, code string) *Finding {
	for i := range r.Findings {
		if r.Findings[i].Code == code {
			return &r.Findings[i]
		}
	}
	return nil
}

func TestStaticValidBaseline(t *testing.T) {
	t.Parallel()
	r := Static(baseline())
	assert.False(t, r.HasErrors(), "baseline must have no errors: %+v", r.Errors())
	assert.Empty(t, r.Warnings(), "baseline must have no warnings: %+v", r.Warnings())
}

func TestStaticChecks(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		mutate   func(*StaticInput)
		wantCode string
		wantSev  Severity
	}{
		{
			name:     "unknown issuer key",
			mutate:   func(in *StaticInput) { in.Sourced.Issuers[0].Config["bogus"] = 1 },
			wantCode: "CFG-ISSUER-CONFIG",
			wantSev:  SeverityError,
		},
		{
			name: "duplicate issuer name",
			mutate: func(in *StaticInput) {
				in.Sourced.Issuers = append(in.Sourced.Issuers, config.IssuerBlock{
					Name: "ci", Type: "static",
				})
			},
			wantCode: "CFG-ISSUER-DUP",
			wantSev:  SeverityError,
		},
		{
			name:     "rule references unknown issuer",
			mutate:   func(in *StaticInput) { in.Sourced.Rules[0].Match.Issuer = "nope" },
			wantCode: "CFG-XREF-ISSUER",
			wantSev:  SeverityError,
		},
		{
			name:     "rule pattern references unknown realm",
			mutate:   func(in *StaticInput) { in.Sourced.Rules[0].Allow[0].Resources = []string{"mystery:x/*"} },
			wantCode: "CFG-XREF-REALM",
			wantSev:  SeverityError,
		},
		{
			name:     "invalid signing algorithm",
			mutate:   func(in *StaticInput) { in.Config.Signing.Algorithm = "RS999" },
			wantCode: "CFG-SIGNING",
			wantSev:  SeverityError,
		},
		{
			name:     "invalid store type",
			mutate:   func(in *StaticInput) { in.Config.Store.Type = "mongodb" },
			wantCode: "CFG-STORE",
			wantSev:  SeverityError,
		},
		{
			name: "github-app instance missing private key",
			mutate: func(in *StaticInput) {
				in.Sourced.Realms[0].Instances[0].Config = map[string]any{"app_id": 1} // no private_key
			},
			wantCode: "CFG-INSTANCE-CONFIG",
			wantSev:  SeverityError,
		},
		{
			name:     "invalid action for realm",
			mutate:   func(in *StaticInput) { in.Sourced.Rules[0].Allow[0].Actions = []core.Action{"totally-not-an-action"} },
			wantCode: "CFG-ACTION",
			wantSev:  SeverityError,
		},
		{
			name:     "unresolvable secret ref",
			mutate:   func(in *StaticInput) { in.Config.Signing.Key = "env:TALMI_VET_DEFINITELY_UNSET_XYZ" },
			wantCode: "CFG-SECRET",
			wantSev:  SeverityError,
		},
		{
			name: "unused issuer is a warning",
			mutate: func(in *StaticInput) {
				in.Sourced.Issuers = append(in.Sourced.Issuers, config.IssuerBlock{
					Name: "orphan", Type: "static",
				})
			},
			wantCode: "CFG-UNUSED-ISSUER",
			wantSev:  SeverityWarn,
		},
		{
			name: "auth login_issuer must be a github-oauth issuer",
			mutate: func(in *StaticInput) {
				in.Config.Auth = &config.AuthConfig{LoginIssuer: "ci", SessionIssuer: "ci"}
			},
			wantCode: "CFG-AUTH-LOGIN",
			wantSev:  SeverityError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			in := baseline()
			tt.mutate(&in)
			r := Static(in)

			f := findByCode(r, tt.wantCode)
			require.NotNilf(t, f, "expected a %q finding; got: %+v", tt.wantCode, r.Findings)
			assert.Equal(t, tt.wantSev, f.Severity)
			if tt.wantSev == SeverityWarn {
				assert.False(t, r.HasErrors(), "an unused-config warning must not make the config invalid")
			}
		})
	}
}

func TestStaticSuggestsCloseIssuerName(t *testing.T) {
	t.Parallel()
	in := baseline()
	in.Sourced.Rules[0].Match.Issuer = "c" // typo of "ci"
	r := Static(in)

	f := findByCode(r, "CFG-XREF-ISSUER")
	require.NotNil(t, f, "got: %+v", r.Findings)
	assert.Contains(t, f.Suggestions, "ci", "should suggest the closest defined issuer")
}

func TestStaticNoRulesWarns(t *testing.T) {
	t.Parallel()
	in := baseline()
	in.Sourced.Rules = nil
	r := Static(in)

	f := findByCode(r, "CFG-NO-RULES")
	require.NotNil(t, f, "got: %+v", r.Findings)
	assert.Equal(t, SeverityWarn, f.Severity)
	assert.False(t, r.HasErrors(), "no rules is a warning, not an error")
}

// TestStaticAcceptsTalmiRealmType guards against flagging "talmi" as an unknown
// realm type: it is valid (authz-vocabulary realm) and handled by buildRealms /
// RealmRegistry, so checkRealms must accept it too.
func TestStaticAcceptsTalmiRealmType(t *testing.T) {
	t.Parallel()
	in := baseline()
	in.Sourced.Realms = append(in.Sourced.Realms, config.RealmBlock{Realm: "talmi", Type: "talmi"})
	in.Realms.Register("talmi", realm.Talmi{})

	r := Static(in)
	assert.Nil(t, findByCode(r, "CFG-REALM-TYPE"),
		"talmi is a valid realm type; findings: %+v", r.Findings)
}

func TestCheckAuditRetentionAndSinks(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		mutate    func(*config.AuditConfig)
		wantError bool
	}{
		{
			"valid retention and stdout sink", func(a *config.AuditConfig) {
				a.Retention = 90 * 24 * time.Hour
				a.Sinks = []string{"stdout"}
			}, false,
		},
		{"zero retention is keep-forever", func(a *config.AuditConfig) { a.Retention = 0 }, false},
		{"negative retention", func(a *config.AuditConfig) { a.Retention = -1 }, true},
		{"unknown sink kind", func(a *config.AuditConfig) { a.Sinks = []string{"bogus"} }, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			is := assert.New(t)
			in := baseline()
			in.Config.Audit = config.AuditConfig{Enabled: true, Type: "memory"}
			tt.mutate(&in.Config.Audit)

			r := Static(in)
			f := findByCode(r, "CFG-AUDIT")
			if tt.wantError {
				is.NotNil(f, "expected a CFG-AUDIT finding; got: %+v", r.Findings)
			} else {
				is.Nil(f, "expected no CFG-AUDIT finding; got: %+v", r.Findings)
			}
		})
	}
}
