package issuers

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/darmiel/talmi/internal/config"
)

func TestStaticIssuer(t *testing.T) {
	t.Parallel()
	iss, err := NewStatic(config.IssuerBlock{
		Name: "ci-tokens",
		Config: map[string]any{
			"token_map": map[string]any{
				"secret-tok": map[string]any{"pipeline": "deploy", "team": "platform"},
				"bad-entry":  "not-a-map", // skipped
			},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, "ci-tokens", iss.Name())

	t.Run("valid token yields attributes", func(t *testing.T) {
		t.Parallel()
		is := assert.New(t)
		p, err := iss.Verify(context.Background(), "secret-tok")
		require.NoError(t, err)
		is.Equal("ci-tokens", p.Issuer)
		is.Equal("deploy", p.Attributes["pipeline"])
	})

	t.Run("unknown token", func(t *testing.T) {
		t.Parallel()
		_, err := iss.Verify(context.Background(), "nope")
		assert.Error(t, err)
	})

	t.Run("malformed entry was skipped", func(t *testing.T) {
		t.Parallel()
		_, err := iss.Verify(context.Background(), "bad-entry")
		assert.Error(t, err)
	})
}

func TestStaticIssuerNoTokenMap(t *testing.T) {
	t.Parallel()
	iss, err := NewStatic(config.IssuerBlock{Name: "empty"})
	require.NoError(t, err)
	_, err = iss.Verify(context.Background(), "anything")
	assert.Error(t, err) // empty map always fails
}
