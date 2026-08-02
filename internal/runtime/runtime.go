package runtime

import (
	"context"
	"errors"
	"fmt"

	"github.com/darmiel/talmi/internal/audit"
	"github.com/darmiel/talmi/internal/config"
	"github.com/darmiel/talmi/internal/core"
	"github.com/darmiel/talmi/internal/engine"
	"github.com/darmiel/talmi/internal/issuers"
	githubprovider "github.com/darmiel/talmi/internal/providers/github"
	"github.com/darmiel/talmi/internal/providers/jfrog"
	"github.com/darmiel/talmi/internal/providers/stub"
	"github.com/darmiel/talmi/internal/realm"
	"github.com/darmiel/talmi/internal/resolver"
	"github.com/darmiel/talmi/internal/secret"
	"github.com/darmiel/talmi/internal/service"
	"github.com/darmiel/talmi/internal/store"
	"github.com/darmiel/talmi/internal/store/postgres"
	"github.com/darmiel/talmi/internal/validation"
)

// Runtime holds a set of components for one config revision
type Runtime struct {
	Service    *service.TokenService
	Issuers    *issuers.Registry
	Realms     *realm.Registry
	Engine     *engine.PolicyManager
	LeaseStore core.LeaseStore
	Auditor    core.Auditor
	Providers  []core.ResourceProvider // for webhook cache invalidation
	Revision   string
}

// stable holds components that persist across reloads.
type stable struct {
	store      core.LeaseStore
	auditor    core.Auditor
	sessionKey []byte
}

func (s stable) Close() error {
	return errors.Join(s.store.Close(), s.auditor.Close())
}

func buildStable(ctx context.Context, cfg *config.Config) (*stable, error) {
	var sessionKey []byte
	if cfg.Signing.Key != "" {
		key, err := secret.Resolve(cfg.Signing.Key)
		if err != nil {
			return nil, fmt.Errorf("resolving signing key: %w", err)
		}
		sessionKey = key
	}
	leaseStore, err := buildStore(ctx, cfg.Store)
	if err != nil {
		return nil, err
	}
	auditor, err := buildAuditor(ctx, cfg.Audit)
	if err != nil {
		_ = leaseStore.Close()
		return nil, err
	}
	return &stable{
		store:      leaseStore,
		auditor:    auditor,
		sessionKey: sessionKey,
	}, nil
}

func buildReloadable(
	ctx context.Context,
	sourced *config.SourcedConfig,
	revision string,
	dev bool,
	stable stable,
) (*Runtime, error) {
	realms, err := buildRealms(sourced.Realms)
	if err != nil {
		return nil, err
	}
	specs, err := config.ExpandProviders(sourced.Realms)
	if err != nil {
		return nil, fmt.Errorf("expanding providers: %w", err)
	}
	providers, err := buildProviders(specs, dev)
	if err != nil {
		return nil, fmt.Errorf("building providers: %w", err)
	}
	issReg, err := issuers.BuildRegistry(ctx, sourced.Issuers, stable.sessionKey)
	if err != nil {
		return nil, fmt.Errorf("building issuer registry: %w", err)
	}
	validRules, err := validation.ValidateRules(sourced.Rules, issReg.KnownIssuers(), realms)
	if err != nil {
		return nil, fmt.Errorf("validating rules: %w", err)
	}
	policy := engine.NewManager(validRules, realms)
	res := resolver.New(providers, realms)
	svc := service.NewTokenService(issReg, policy, res, stable.store, stable.auditor, revision)
	return &Runtime{
		Service:    svc,
		Issuers:    issReg,
		Realms:     realms,
		Engine:     policy,
		LeaseStore: stable.store,
		Auditor:    stable.auditor,
		Revision:   revision,
	}, nil
}

func buildRealms(realms []config.RealmBlock) (*realm.Registry, error) {
	reg := realm.NewRegistry()
	for _, rb := range realms {
		var sem realm.Semantics
		switch rb.Type {
		case "github-app":
			sem = realm.GitHub{}
		case "artifactory":
			sem = realm.Artifactory{}
		case "talmi":
			sem = realm.Talmi{}
		default:
			return nil, fmt.Errorf("realm %q: unknown type: %s", rb.Realm, rb.Type)
		}
		reg.Register(rb.Realm, sem)
	}
	return reg, nil
}

func buildProviders(specs []config.ProviderSpec, dev bool) ([]core.ResourceProvider, error) {
	providers := make([]core.ResourceProvider, 0, len(specs))
	for _, spec := range specs {
		p, err := buildProvider(spec, dev)
		if err != nil {
			return nil, fmt.Errorf("provider %q: %w", spec.Name, err)
		}
		providers = append(providers, p)
	}
	return providers, nil
}

func buildProvider(spec config.ProviderSpec, dev bool) (core.ResourceProvider, error) {
	if dev {
		return stub.New(spec.Name, spec.Realm,
			stub.WithResources(spec.Capability.Resources...),
			stub.WithMaxActions(spec.Capability.MaxActions...),
		), nil
	}
	switch spec.Type {
	case "github-app":
		key, err := secret.ResolveString(spec.PrivateKey)
		if err != nil {
			return nil, err
		}
		return githubprovider.New(spec.Name, spec.Realm, githubprovider.ProviderConfig{
			AppID:         spec.AppID,
			PrivateKey:    key,
			ServerBaseURL: spec.Server,
		})
	case "artifactory":
		tok, err := secret.ResolveString(spec.AdminToken)
		if err != nil {
			return nil, err
		}
		return jfrog.New(spec.Name, spec.Realm, jfrog.ProviderConfig{
			Server:     spec.BaseURL,
			Token:      tok,
			Groups:     spec.Groups,
			Resources:  spec.Capability.Resources,
			MaxActions: spec.Capability.MaxActions,
		})
	default:
		return nil, fmt.Errorf("unknown provider type %q", spec.Type)
	}
}

func buildStore(ctx context.Context, cfg config.StoreConfig) (core.LeaseStore, error) {
	switch cfg.Type {
	case "", "memory":
		return store.NewMemoryLeaseStore(), nil
	case "postgres":
		dsn, err := secret.ResolveString(cfg.DSN)
		if err != nil {
			return nil, fmt.Errorf("resolving postgres DSN: %w", err)
		}
		return postgres.OpenLeaseStore(ctx, dsn)
	default:
		return nil, fmt.Errorf("unknown store type %q", cfg.Type)
	}
}

func buildAuditor(ctx context.Context, cfg config.AuditConfig) (core.Auditor, error) {
	if !cfg.Enabled {
		return audit.NewNoopAuditor(), nil
	}
	switch cfg.Type {
	case "postgres":
		dsn, err := secret.ResolveString(cfg.DSN)
		if err != nil {
			return nil, fmt.Errorf("resolving postgres DSN: %w", err)
		}
		return postgres.OpenAuditor(ctx, dsn)
	case "memory":
		return audit.NewInMemoryAuditor(), nil
	case "noop":
		return audit.NewNoopAuditor(), nil
	default:
		return nil, fmt.Errorf("unknown audit type %q", cfg.Type)
	}
}
