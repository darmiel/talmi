package cmd

import (
	"context"
	"crypto/rand"
	"fmt"
	"os"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/darmiel/talmi/internal/audit"
	"github.com/darmiel/talmi/internal/cliconfig"
	"github.com/darmiel/talmi/internal/config"
	"github.com/darmiel/talmi/internal/engine"
	"github.com/darmiel/talmi/internal/issuers"
	"github.com/darmiel/talmi/internal/providers"
	"github.com/darmiel/talmi/internal/service"
	"github.com/darmiel/talmi/internal/store"
	"github.com/darmiel/talmi/pkg/client"
)

type Factory struct {
	// RemoteAddr is the address of the Talmi server to connect to.
	RemoteAddr string

	CLIConfigPath string
	LogLevel      string
	LogFormat     string

	// Command-specific flags
	PolicyPath string // contains the "main" Talmi configuration => rules and policies used for minting
}

func NewFactory() *Factory {
	return &Factory{}
}

// GetClient returns an authenticated HTTP client for remote operations.
func (f *Factory) GetClient() (*client.Client, error) {
	server := f.RemoteAddr // prio 1: command-line flag
	if server == "" {
		server = viper.GetString(TalmiAddrKey) // prio 2: config/env
	}
	if server == "" {
		return nil, fmt.Errorf("server address not configured (use --server or set TALMI_ADDR)")
	}

	var token string
	if cfg, err := cliconfig.Load(); err == nil {
		if cred, err := cfg.GetCredential(server); err == nil { // token prio 1: saved credential
			token = cred.Token
		}
	}

	if envToken := os.Getenv("TALMI_TOKEN"); envToken != "" { // token prio 2: env var
		token = envToken
	}

	return client.New(server, client.WithAuthToken(token)), nil
}

func (f *Factory) LoadPolicyConfig() (*config.Config, error) {
	if f.PolicyPath == "" {
		return nil, fmt.Errorf("policy file not specified (use --policy)")
	}
	return config.Load(f.PolicyPath)
}

func (f *Factory) GetLocalService(ctx context.Context) (*service.TokenService, error) {
	cfg, err := f.LoadPolicyConfig()
	if err != nil {
		return nil, fmt.Errorf("loading policy file: %w", err)
	}

	issReg, err := issuers.BuildRegistry(ctx, cfg.Issuers)
	if err != nil {
		return nil, fmt.Errorf("building issuer registry: %w", err)
	}

	signingKey := make([]byte, 32)
	if _, err := rand.Read(signingKey); err != nil {
		return nil, fmt.Errorf("generating signing key: %w", err)
	}
	provReg, err := providers.BuildRegistry(cfg.Providers, signingKey)
	if err != nil {
		return nil, fmt.Errorf("building provider registry: %w", err)
	}

	return service.NewTokenService(
		issReg,
		provReg,
		engine.NewManager(cfg.Rules),
		audit.NewNoopAuditor(),        // for local CLI operations, we don't do auditing
		store.NewInMemoryTokenStore(), // for local CLI operations, in-memory store is sufficient
	), nil
}

func (f *Factory) bindPolicyFlag(flags *pflag.FlagSet) {
	flags.StringVarP(&f.PolicyPath, "policy", "f", "", "The Talmi policy config file to use")
}
