package configvet

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestResolvePosition(t *testing.T) {
	t.Parallel()

	// A single issuers file is a top-level YAML sequence of blocks, matching how
	// the sourced tree stores them.
	src := Source{
		File: "issuers/ci.yaml",
		Data: []byte("- name: cc\n  type: oidc\n  issuerurl: https://idp\n  client_id: c\n"),
	}

	t.Run("resolves a present key to its line", func(t *testing.T) {
		t.Parallel()
		is := assert.New(t)
		got := resolve(src, "$[0].issuerurl")
		is.Equal("issuers/ci.yaml", got.File)
		is.Equal(3, got.Line, "issuerurl is on line 3")
		is.Positive(got.Column)
	})

	t.Run("unresolvable path degrades gracefully", func(t *testing.T) {
		t.Parallel()
		is := assert.New(t)
		got := resolve(src, "$[0].nonexistent")
		is.Equal("issuers/ci.yaml", got.File, "file is still reported")
		is.Zero(got.Line, "line is zero when the path cannot be resolved")
		is.Zero(got.Column)
	})

	t.Run("invalid path expression degrades gracefully", func(t *testing.T) {
		t.Parallel()
		is := assert.New(t)
		got := resolve(src, "!!!not a path")
		is.Equal("issuers/ci.yaml", got.File)
		is.Zero(got.Line)
	})
}
