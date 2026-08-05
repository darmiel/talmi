package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIssuerTypes(t *testing.T) {
	t.Parallel()
	// sorted, and exactly the four registered issuer types
	assert.Equal(t, []string{
		IssuerTypeGitHubOAuth,
		IssuerTypeOIDC,
		IssuerTypeStatic,
		IssuerTypeTalmiSession,
	}, IssuerTypes())
}
