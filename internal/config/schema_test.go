package config

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateSchema(t *testing.T) {
	t.Parallel()

	t.Run("issuers: discriminated union by type", func(t *testing.T) {
		t.Parallel()
		is := assert.New(t)
		b, err := GenerateSchema("issuers")
		require.NoError(t, err)

		var doc map[string]any
		require.NoError(t, json.Unmarshal(b, &doc), "schema must be valid JSON")

		s := string(b)
		is.Contains(s, `"const": "oidc"`)
		is.Contains(s, "issuer_url")
		is.Contains(s, "client_id")
		is.Contains(s, `"const": "static"`)
		is.Contains(s, "token_map")
		is.Contains(s, `"const": "github-oauth"`)
		is.Contains(s, `"const": "talmi-session"`)
		is.Contains(s, `"oneOf"`)
	})

	t.Run("realms: instance creds per realm type", func(t *testing.T) {
		t.Parallel()
		is := assert.New(t)
		b, err := GenerateSchema("realms")
		require.NoError(t, err)

		var doc map[string]any
		require.NoError(t, json.Unmarshal(b, &doc))

		s := string(b)
		is.Contains(s, `"const": "github-app"`)
		is.Contains(s, "app_id")
		is.Contains(s, "private_key")
		is.Contains(s, `"const": "artifactory"`)
		is.Contains(s, "admin_token")
		is.Contains(s, "groups")
	})

	t.Run("rules and config are valid JSON schemas", func(t *testing.T) {
		t.Parallel()
		for _, target := range []string{"config", "rules"} {
			b, err := GenerateSchema(target)
			require.NoErrorf(t, err, "target %q", target)
			var doc map[string]any
			require.NoErrorf(t, json.Unmarshal(b, &doc), "target %q must be valid JSON", target)
		}
	})

	t.Run("unknown target errors", func(t *testing.T) {
		t.Parallel()
		_, err := GenerateSchema("mystery")
		assert.Error(t, err)
	})

	t.Run("durations are strings, not integers", func(t *testing.T) {
		t.Parallel()
		is := assert.New(t)
		doc := decodeSchema(t, "config")

		// SyncConfig.interval and AuthConfig.session_ttl are Go time.Duration
		// but are written as duration strings ("8h", "5m"), so must be typed
		// as string in the schema.
		is.Equal("string", defProp(doc, "SyncConfig", "interval")["type"])
		is.Equal("string", defProp(doc, "AuthConfig", "session_ttl")["type"])
	})

	t.Run("conditions accept dynamic shorthand objects", func(t *testing.T) {
		t.Parallel()
		is := assert.New(t)
		doc := decodeSchema(t, "rules")

		// Conditions are parsed dynamically (e.g. { teams: { contains: "..." } })
		// so the schema must accept any object, not a fixed struct.
		cond := defProp(doc, "Match", "condition")
		is.Equal("object", cond["type"])
		is.NotContains(cond, "properties", "condition schema must not pin fixed keys")
		is.NotContains(cond, "additionalProperties", "condition schema must stay permissive")
	})

	t.Run("condition and expr are mutually exclusive", func(t *testing.T) {
		t.Parallel()
		is := assert.New(t)
		doc := decodeSchema(t, "rules")

		match := schemaDef(doc, "Match")
		not, ok := match["not"].(map[string]any)
		require.True(t, ok, "Match must carry a `not` constraint")
		req, ok := not["required"].([]any)
		require.True(t, ok)
		is.ElementsMatch([]any{"condition", "expr"}, req)
	})
}

func decodeSchema(t *testing.T, target string) map[string]any {
	t.Helper()
	b, err := GenerateSchema(target)
	require.NoError(t, err)
	var doc map[string]any
	require.NoError(t, json.Unmarshal(b, &doc))
	return doc
}

func schemaDef(doc map[string]any, name string) map[string]any {
	defs, _ := doc["$defs"].(map[string]any)
	def, _ := defs[name].(map[string]any)
	return def
}

func defProp(doc map[string]any, def, prop string) map[string]any {
	props, _ := schemaDef(doc, def)["properties"].(map[string]any)
	p, _ := props[prop].(map[string]any)
	return p
}
