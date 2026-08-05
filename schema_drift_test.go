package main

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/darmiel/talmi/internal/config"
)

// TestCommittedSchemasUpToDate guards against the committed JSON schemas drifting
// from the config types. Regenerate with `make schema` if this fails.
func TestCommittedSchemasUpToDate(t *testing.T) {
	t.Parallel()
	for _, target := range []string{"config", "issuers", "realms", "rules"} {
		t.Run(target, func(t *testing.T) {
			t.Parallel()
			want, err := config.GenerateSchema(target)
			require.NoError(t, err)
			want = append(want, '\n')

			got, err := os.ReadFile("docs/schema/" + target + ".schema.json")
			require.NoError(t, err, "missing committed schema; run 'make schema'")
			assert.Equal(t, string(want), string(got),
				"docs/schema/%s.schema.json is stale; run 'make schema'", target)
		})
	}
}
