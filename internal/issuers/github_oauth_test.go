package issuers

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/darmiel/talmi/internal/config"
)

func TestGitHubOAuthIssuerVerify(t *testing.T) {
	t.Parallel()
	is := assert.New(t)

	server := newMockGitHubServer(t, false)
	iss, err := NewGitHubOAuthIssuer("gh-human", config.GitHubOAuthConfig{Server: server})
	require.NoError(t, err)

	p, err := iss.Verify(context.Background(), "gho_testtoken")
	require.NoError(t, err)
	is.Equal("alice", p.ID)
	is.Equal("gh-human", p.Issuer)
	is.Equal("alice", p.Attributes["login"])
	// teams span both pages (pagination), orgs deduped
	is.ElementsMatch([]string{"acme/admins", "acme/deployers"}, p.Attributes["teams"])
	is.Equal([]string{"acme"}, p.Attributes["orgs"])
}

func TestGitHubOAuthIssuerAPIError(t *testing.T) {
	t.Parallel()
	server := newMockGitHubServer(t, true) // /user returns 500
	iss, err := NewGitHubOAuthIssuer("gh-human", config.GitHubOAuthConfig{Server: server})
	require.NoError(t, err)

	_, err = iss.Verify(context.Background(), "tok")
	assert.Error(t, err)
}
