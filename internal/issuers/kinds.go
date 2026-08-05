package issuers

import (
	"context"

	"github.com/darmiel/talmi/internal/config"
	"github.com/darmiel/talmi/internal/core"
)

// IssuerDeps carries dependencies some issuers need at construction time.
type IssuerDeps struct {
	Signer *SessionSigner
}

// IssuerKind knows how to build one issuer type from its typed config.
type IssuerKind struct {
	Type  string
	Build func(ctx context.Context, name string, cfg config.IssuerConfig, deps IssuerDeps) (core.Issuer, error)
}

var issuerKinds = map[string]IssuerKind{
	config.IssuerTypeOIDC:         {Type: config.IssuerTypeOIDC, Build: buildOIDC},
	config.IssuerTypeStatic:       {Type: config.IssuerTypeStatic, Build: buildStatic},
	config.IssuerTypeGitHubOAuth:  {Type: config.IssuerTypeGitHubOAuth, Build: buildGitHubOAuth},
	config.IssuerTypeTalmiSession: {Type: config.IssuerTypeTalmiSession, Build: buildTalmiSession},
}

func buildOIDC(ctx context.Context, name string, cfg config.IssuerConfig, _ IssuerDeps) (core.Issuer, error) {
	c, ok := cfg.(*config.OIDCConfig)
	if !ok {
		return nil, config.ErrInvalidConfigType
	}
	return NewOIDCIssuer(ctx, name, *c)
}

func buildStatic(_ context.Context, name string, cfg config.IssuerConfig, _ IssuerDeps) (core.Issuer, error) {
	c, ok := cfg.(*config.StaticConfig)
	if !ok {
		return nil, config.ErrInvalidConfigType
	}
	return NewStatic(name, *c)
}

func buildGitHubOAuth(_ context.Context, name string, cfg config.IssuerConfig, _ IssuerDeps) (core.Issuer, error) {
	c, ok := cfg.(*config.GitHubOAuthConfig)
	if !ok {
		return nil, config.ErrInvalidConfigType
	}
	return NewGitHubOAuthIssuer(name, *c)
}

func buildTalmiSession(_ context.Context, name string, cfg config.IssuerConfig, deps IssuerDeps) (core.Issuer, error) {
	c, ok := cfg.(*config.TalmiSessionConfig)
	if !ok {
		return nil, config.ErrInvalidConfigType
	}
	return NewTalmiSessionIssuer(name, *c, deps.Signer)
}
