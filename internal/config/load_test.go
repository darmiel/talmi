package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writeBootstrap(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "talmi.yaml")
	require.NoError(t, os.WriteFile(p, []byte(content), 0o600))
	return p
}

// A representative, fully-keyed bootstrap must still load under strict decoding.
// This guards against over-strictness, in particular that arbitrary keys in the
// rate_limit.costs map (a map, not struct fields) are not mistaken for unknown fields.
func TestLoadAcceptsValidConfig(t *testing.T) {
	t.Parallel()
	p := writeBootstrap(t, `
grade: prod
signing:
  algorithm: ES256
  key: file:/run/secrets/k.pem
store:
  type: postgres
  dsn: env:DSN
audit:
  enabled: true
  type: postgres
  dsn: env:ADSN
  retention: 2160h
rate_limit:
  enabled: true
  backend: memory
  ip: { capacity: 60, refill_per_sec: 1 }
  principal: { capacity: 120, refill_per_sec: 2 }
  costs:
    issue: { auth_error: 12 }
    task_trigger: { success: 10 }
issuers: { include: [ "issuers.d/*.yaml" ] }
realms: { include: [ "realms.d/*.yaml" ] }
rules: { include: [ "rules.d/*.yaml" ] }
`)
	cfg, err := Load(p)
	require.NoError(t, err)
	assert.Equal(t, "prod", cfg.Grade)
	require.NotNil(t, cfg.RateLimit)
	assert.True(t, cfg.RateLimit.Enabled)
	assert.Equal(t, 12, cfg.RateLimit.Costs["issue"]["auth_error"],
		"arbitrary cost-map keys must survive strict decoding")
}

func TestLoadRejectsUnknownTopLevelKey(t *testing.T) {
	t.Parallel()
	p := writeBootstrap(t, "grade: prod\nbogus: 1\n")
	_, err := Load(p)
	require.Error(t, err, "a typo'd top-level key must fail closed, not be silently ignored")
	assert.Contains(t, err.Error(), "bogus")
}

func TestLoadRejectsUnknownNestedKey(t *testing.T) {
	t.Parallel()
	p := writeBootstrap(t, "audit:\n  enabled: true\n  wawawa: 1\n")
	_, err := Load(p)
	require.Error(t, err, "a typo'd nested key (audit.wawawa) must fail closed")
	assert.Contains(t, err.Error(), "wawawa")
}
