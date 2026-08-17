package runtime

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/darmiel/talmi/internal/audit"
	"github.com/darmiel/talmi/internal/backend"
	"github.com/darmiel/talmi/internal/capability"
	"github.com/darmiel/talmi/internal/config"
	"github.com/darmiel/talmi/internal/configvet"
	"github.com/darmiel/talmi/internal/core"
	"github.com/darmiel/talmi/internal/engine"
	"github.com/darmiel/talmi/internal/issuers"
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
	Service             *service.TokenService
	Issuers             *issuers.Registry
	Realms              *realm.Registry
	Engine              *engine.PolicyManager
	LeaseStore          core.LeaseStore
	Auditor             core.Auditor
	Recorder            *audit.Recorder
	Providers           []core.ResourceProvider // for webhook cache invalidation
	ProviderDescriptors []ProviderDescriptor    // static metadata, idx-aligned with Providers
	Revision            string
}

// ProviderDescriptor is static metadata about one built provider instance.
type ProviderDescriptor struct {
	Name  string
	Realm string
	Type  string
	Mode  string // dicsovery mode: static or api
}

// stable holds components that persist across reloads.
type stable struct {
	store   core.LeaseStore
	auditor core.Auditor
	sinks   []audit.Sink
	signer  *issuers.SessionSigner
}

func (s stable) Close() error {
	errs := []error{s.store.Close(), s.auditor.Close()}
	for _, sink := range s.sinks {
		errs = append(errs, sink.Close())
	}
	return errors.Join(errs...)
}

func buildStable(ctx context.Context, cfg *config.Config, dev bool) (*stable, error) {
	signer, err := buildSigner(cfg.Signing, dev)
	if err != nil {
		return nil, err
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
	sinks, err := buildSinks(cfg.Audit)
	if err != nil {
		_ = leaseStore.Close()
		_ = auditor.Close()
		return nil, err
	}
	return &stable{
		store:   leaseStore,
		auditor: auditor,
		sinks:   sinks,
		signer:  signer,
	}, nil
}

func buildReloadable(
	ctx context.Context,
	cfg *config.Config,
	sourced *config.SourcedConfig,
	revision string,
	dev bool,
	stable stable,
) (*Runtime, error) {
	sourced.Realms, _ = config.NormalizeRealms(sourced.Realms)

	realms, err := buildRealms(sourced.Realms)
	if err != nil {
		return nil, err
	}
	specs, err := config.ExpandProviders(sourced.Realms)
	if err != nil {
		return nil, fmt.Errorf("expanding providers: %w", err)
	}
	providers, descriptors, err := buildProviders(specs, dev)
	if err != nil {
		return nil, fmt.Errorf("building providers: %w", err)
	}
	issReg, err := issuers.BuildRegistry(ctx, sourced.Issuers, stable.signer)
	if err != nil {
		return nil, fmt.Errorf("building issuer registry: %w", err)
	}

	// full config validation
	if !dev {
		report := configvet.Static(configvet.StaticInput{
			Config:  cfg,
			Sourced: sourced,
			Realms:  realms,
		})
		for _, f := range report.Findings {
			ev := log.Ctx(ctx).Warn()
			if f.Severity == configvet.SeverityError {
				ev = log.Ctx(ctx).Error()
			}
			ev.
				Str("code", f.Code).
				Str("location", f.Location).
				Msgf("config: %s", f.Message)
		}
		if report.HasErrors() {
			return nil,
				fmt.Errorf("configuration is invalid: %d error(s) found (run 'talmi config vet' for details)",
					len(report.Errors()))
		}
	}

	// validate rules compiles expr as well, so we need to "re-verify" the rules.
	validRules, err := validation.ValidateRules(sourced.Rules, issReg.KnownIssuers(), realms)
	if err != nil {
		return nil, fmt.Errorf("validating rules: %w", err)
	}
	policy := engine.NewManager(validRules, realms)
	res := resolver.New(providers, realms)
	rec := audit.NewRecorder(stable.auditor, stable.sinks...)
	svc := service.NewTokenService(issReg, policy, res, stable.store, rec, revision)
	return &Runtime{
		Service:             svc,
		Issuers:             issReg,
		Realms:              realms,
		Engine:              policy,
		LeaseStore:          stable.store,
		Auditor:             stable.auditor,
		Recorder:            rec,
		Providers:           providers,
		ProviderDescriptors: descriptors,
		Revision:            revision,
	}, nil
}

func buildRealms(realms []config.RealmBlock) (*realm.Registry, error) {
	reg := realm.NewRegistry()
	seen := make(map[string]struct{})
	for _, rb := range realms {
		sem, ok := realm.SemanticsFor(rb.Type)
		if !ok {
			return nil, fmt.Errorf("realm %q: unknown type: %s", rb.Realm, rb.Type)
		}
		if _, dup := seen[rb.Realm]; dup {
			return nil, fmt.Errorf("realm %q: duplicate realm name", rb.Realm)
		}
		seen[rb.Realm] = struct{}{}
		reg.Register(rb.Realm, sem)
	}
	return reg, nil
}

func buildSigner(cfg config.SigningConfig, dev bool) (*issuers.SessionSigner, error) {
	if cfg.Key == "" {
		if dev {
			log.Warn().Msg("runtime: --dev generated an ephemeral ES256 session signing key (sessions won't survive restart)")
			return issuers.NewEphemeralSigner()
		}
		return nil, nil // talmi issuer will error
	}
	key, err := secret.ResolveString(cfg.Key)
	if err != nil {
		return nil, fmt.Errorf("resolving signing key: %w", err)
	}
	signer, err := issuers.NewSessionSigner(cfg.Algorithm, []byte(key))
	if err != nil {
		return nil, fmt.Errorf("building session signer: %w", err)
	}
	alg := cfg.Algorithm
	if alg == "" {
		alg = "ES256"
	}
	log.Info().Str("algorithm", alg).Msg("runtime: session signer initialized")
	return signer, nil
}

func buildProviders(specs []config.ProviderSpec, dev bool) ([]core.ResourceProvider, []ProviderDescriptor, error) {
	providers := make([]core.ResourceProvider, 0, len(specs))
	descriptors := make([]ProviderDescriptor, 0, len(specs))
	for _, spec := range specs {
		p, d, err := buildProvider(spec, dev)
		if err != nil {
			return nil, nil, fmt.Errorf("provider %q: %w", spec.Name, err)
		}
		providers = append(providers, p)
		descriptors = append(descriptors, d)
	}
	return providers, descriptors, nil
}

func buildProvider(spec config.ProviderSpec, dev bool) (core.ResourceProvider, ProviderDescriptor, error) {
	b, ok := backend.Lookup(spec.Type)
	if !ok {
		return nil, ProviderDescriptor{}, fmt.Errorf("unknown provider type %q", spec.Type)
	}
	mode := capability.Mode(spec.Capability.Discovery, b.SupportsAPIDiscovery)
	descriptor := ProviderDescriptor{
		Name:  spec.Name,
		Realm: spec.Realm,
		Type:  spec.Type,
		Mode:  mode,
	}
	declared := core.Capability{
		Realm:      spec.Realm,
		Resources:  spec.Capability.Resources,
		MaxActions: spec.Capability.MaxActions,
	}
	var base core.ResourceProvider
	if dev {
		log.Debug().
			Str("provider", spec.Name).
			Str("realm", spec.Realm).
			Msg("runtime: building provider (dev stub)")

		base = stub.New(spec.Name, spec.Realm,
			stub.WithResources(spec.Capability.Resources...),
			stub.WithMaxActions(spec.Capability.MaxActions...),
		)
		if mode == "api" && len(spec.Capability.Resources) == 0 && len(spec.Capability.MaxActions) == 0 {
			log.Warn().
				Str("realm", spec.Realm).
				Str("instance", spec.Name).
				Msg("runtime: realm uses api discovery with no static ceiling (under --dev it serves nothing)")
		}
	} else {
		log.Debug().
			Str("provider", spec.Name).
			Str("realm", spec.Realm).
			Str("type", spec.Type).
			Msg("runtime: building provider")

		p, err := b.Build(backend.BuildInput{Spec: spec})
		if err != nil {
			return nil, ProviderDescriptor{}, err
		}
		base = p
	}

	return capability.Decorate(base, b.Semantics, mode, declared), descriptor, nil
}

func buildStore(ctx context.Context, cfg config.StoreConfig) (core.LeaseStore, error) {
	switch cfg.Type {
	case "", "memory":
		log.Info().
			Str("type", "memory").
			Msg("runtime: lease store initialized")
		return store.NewMemoryLeaseStore(), nil
	case "postgres":
		dsn, err := secret.ResolveString(cfg.DSN)
		if err != nil {
			return nil, fmt.Errorf("resolving postgres DSN: %w", err)
		}
		st, err := postgres.OpenLeaseStore(ctx, dsn, connectTimeoutOr(cfg.ConnectTimeout))
		if err != nil {
			return nil, err
		}
		log.Info().
			Str("type", "postgres").
			Msg("runtime: lease store initialized")
		return st, nil
	default:
		return nil, fmt.Errorf("unknown store type %q", cfg.Type)
	}
}

func buildAuditor(ctx context.Context, cfg config.AuditConfig) (core.Auditor, error) {
	if !cfg.Enabled {
		log.Warn().Msg("runtime: auditing is disabled (noop auditor)")
		return audit.NewNoopAuditor(), nil
	}
	switch cfg.Type {
	case "postgres":
		dsn, err := secret.ResolveString(cfg.DSN)
		if err != nil {
			return nil, fmt.Errorf("resolving postgres DSN: %w", err)
		}
		a, err := postgres.OpenAuditor(ctx, dsn, connectTimeoutOr(cfg.ConnectTimeout))
		if err != nil {
			return nil, err
		}
		log.Info().
			Str("type", "postgres").
			Msg("runtime: auditor initialized")
		return a, nil
	case "memory":
		log.Info().
			Str("type", "memory").
			Msg("runtime: auditor initialized")
		return audit.NewInMemoryAuditor(), nil
	case "noop":
		log.Warn().
			Msg("runtime: auditor type is noop (audit records are discarded)")
		return audit.NewNoopAuditor(), nil
	default:
		return nil, fmt.Errorf("unknown audit type %q", cfg.Type)
	}
}

func buildSinks(cfg config.AuditConfig) ([]audit.Sink, error) {
	var sinks []audit.Sink
	for _, kind := range cfg.Sinks {
		switch kind {
		case "stdout":
			sinks = append(sinks, audit.NewStdoutSink(os.Stdout))
			log.Info().Str("sink", "stdout").Msg("runtime: audit sink enabled")
		default:
			return nil, fmt.Errorf("unknown audit sink type %q", kind)
		}
	}
	return sinks, nil
}

func connectTimeoutOr(d time.Duration) time.Duration {
	if d <= 0 {
		return 10 * time.Second
	}
	return d
}
