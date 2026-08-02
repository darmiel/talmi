package issuers

import (
	"context"
	"fmt"

	"github.com/google/go-github/v80/github"

	"github.com/darmiel/talmi/internal/config"
	"github.com/darmiel/talmi/internal/core"
	githubprovider "github.com/darmiel/talmi/internal/providers/github"
)

var _ core.Issuer = (*GitHubOAuthIssuer)(nil)

// GitHubOAuthIssuer verifies a GHES OAuth access token by calling the GitHub api to resolve the user's login
// and team memberships.
type GitHubOAuthIssuer struct {
	name      string
	serverURL string // empty = github.com
}

func NewGitHubOAuthIssuer(cfg config.IssuerBlock) (*GitHubOAuthIssuer, error) {
	server, _ := cfg.Config["server"].(string)
	return &GitHubOAuthIssuer{
		name:      cfg.Name,
		serverURL: server,
	}, nil
}

func (i *GitHubOAuthIssuer) Name() string {
	return i.name
}

func (i *GitHubOAuthIssuer) Verify(ctx context.Context, token string) (*core.Principal, error) {
	client, err := githubprovider.NewRawClient(token, i.serverURL)
	if err != nil {
		return nil, fmt.Errorf("creating github client: %w", err)
	}
	user, _, err := client.Users.Get(ctx, "")
	if err != nil {
		return nil, fmt.Errorf("resolving user info: %w", err)
	}
	teams, err := listAllUserTeams(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("listing teams: %w", err)
	}

	teamSlugs := make([]string, 0, len(teams))
	orgSet := make(map[string]struct{})
	var orgs []string
	for _, t := range teams {
		org := t.GetOrganization().GetLogin()
		teamSlugs = append(teamSlugs, fmt.Sprintf("%s/%s", org, t.GetSlug()))
		if _, ok := orgSet[org]; !ok {
			orgSet[org] = struct{}{}
			orgs = append(orgs, org)
		}
	}

	return &core.Principal{
		ID:     user.GetLogin(),
		Issuer: i.name,
		Attributes: map[string]any{
			"login": user.GetLogin(),
			"teams": teamSlugs,
			"orgs":  orgs,
		},
	}, nil
}

func listAllUserTeams(ctx context.Context, client *github.Client) ([]*github.Team, error) {
	var all []*github.Team
	opt := &github.ListOptions{PerPage: 100}
	for {
		page, resp, err := client.Teams.ListUserTeams(ctx, opt)
		if err != nil {
			return nil, err
		}
		all = append(all, page...)
		if resp.NextPage == 0 {
			return all, nil
		}
		opt.Page = resp.NextPage
	}
}
