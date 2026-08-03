package github

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/go-github/v80/github"
	"github.com/rs/zerolog/log"

	"github.com/darmiel/talmi/internal/core"
)

func (p *Provider) discoveredCapability(ctx context.Context) (*discovered, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.cached != nil && time.Now().Before(p.cached.expiresAt) {
		log.Ctx(ctx).Debug().
			Str("provider", p.name).
			Msg("github: capability cache hit")
		return p.cached.data, nil
	}

	log.Ctx(ctx).Debug().
		Str("provider", p.name).
		Msg("github: capability cache miss, discovering")
	d, err := p.discover(ctx)
	if err != nil {
		return nil, fmt.Errorf("discovering github capabilities for %q: %w", p.name, err)
	}
	p.cached = &cachedCapability{
		data:      d,
		expiresAt: time.Now().Add(p.capTTL),
	}
	log.Ctx(ctx).Info().
		Str("provider", p.name).
		Int("owners", len(d.installByOwner)).
		Dur("ttl", p.capTTL).
		Msg("github: capabilities discovered")
	return d, nil
}

func (p *Provider) discoverViaAPI(ctx context.Context) (*discovered, error) {
	appClient, err := NewClient(p.appID, p.privateKey, p.serverBaseURL)
	if err != nil {
		return nil, fmt.Errorf("creating github app client: %w", err)
	}

	app, _, err := appClient.Apps.Get(ctx, "") // "" = authenticated app
	if err != nil {
		return nil, fmt.Errorf("getting app: %w", err)
	}

	appActions, err := permsToActions(app.GetPermissions())
	if err != nil {
		return nil, fmt.Errorf("mapping app permissions to actions: %w", err)
	}

	d := &discovered{
		appActions:     appActions,
		installByOwner: make(map[string]int64),
		reposByOwner:   make(map[string][]string),
	}

	installs, _, err := appClient.Apps.ListInstallations(ctx, nil) // TODO: paginate
	if err != nil {
		return nil, fmt.Errorf("listing installations: %w", err)
	}
	for _, inst := range installs {
		owner := inst.GetAccount().GetLogin()
		d.installByOwner[owner] = inst.GetID()

		instClient, err := InstallationTokenClient(ctx, appClient, inst.GetID())
		if err != nil {
			return nil, fmt.Errorf("creating installation client for owner %q: %w", owner, err)
		}

		repos, _, err := instClient.Apps.ListRepos(ctx, nil) // TODO: paginate
		if err != nil {
			return nil, fmt.Errorf("listing repos for owner %q: %w", owner, err)
		}
		for _, repo := range repos.Repositories {
			d.reposByOwner[owner] = append(d.reposByOwner[owner], repo.GetName())
		}
	}

	return d, nil
}

func permsToActions(perms *github.InstallationPermissions) ([]core.Action, error) {
	if perms == nil {
		return nil, nil
	}
	b, err := json.Marshal(perms)
	if err != nil {
		return nil, fmt.Errorf("marshaling permissions: %w", err)
	}
	var m map[string]string
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("unmarshaling permissions to map: %w", err)
	}

	actions := make([]core.Action, 0, len(m))
	for perm, lvl := range m {
		action := core.Action(fmt.Sprintf("%s:%s", perm, lvl))
		actions = append(actions, action)
	}
	return actions, nil
}
