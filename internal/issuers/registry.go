package issuers

import (
	"context"
	"fmt"
	"strings"

	"github.com/darmiel/talmi/internal/config"
	"github.com/darmiel/talmi/internal/core"
)

type Registry struct {
	issuers map[string]core.Issuer // name -> issuer
	urlMap  map[string]string      // issuer_url -> name
}

func (r *Registry) Get(name string) (core.Issuer, bool) {
	iss, ok := r.issuers[name]
	return iss, ok
}

func (r *Registry) IdentifyIssuer(token string) (core.Issuer, error) {
	var name string // the name of the issuer

	switch {
	case strings.HasPrefix(token, "eyJ"): // likely a JWT
		url, err := ExtractIssuerURL(token)
		if err != nil {
			return nil, fmt.Errorf("extracting issuer URL: %w (is it a valid JWT?)", err)
		}
		var ok bool
		if name, ok = r.urlMap[url]; !ok {
			return nil, fmt.Errorf("no issuer found for URL: %s", url)
		}
	default: // it may be a static issuer with a raw token
		k, _, ok := r.findStaticIssuerByToken(token)
		if !ok {
			return nil, fmt.Errorf("no static issuer found for provided token")
		}
		name = k
	}

	iss, ok := r.issuers[name]
	if !ok {
		return nil, fmt.Errorf("issuer %q not found in registry", name)
	}
	return iss, nil
}

func (r *Registry) KnownIssuers() map[string]struct{} {
	known := make(map[string]struct{})
	for name := range r.issuers {
		known[name] = struct{}{}
	}
	return known
}

func BuildRegistry(ctx context.Context, blocks []config.IssuerBlock, signer *SessionSigner) (*Registry, error) {
	issuers := make(map[string]core.Issuer)
	urlMap := make(map[string]string)

	for _, block := range blocks {
		if block.Name == "" {
			return nil, fmt.Errorf("issuer is missing a name")
		}

		var (
			iss       core.Issuer
			issuerURL string
			err       error
		)

		typed, err := config.DecodeIssuerConfig(block)
		if err != nil {
			return nil, fmt.Errorf("building issuer %q: %w", block.Name, err)
		}
		switch c := typed.(type) {
		case *config.OIDCConfig:
			iss, err = NewOIDCIssuer(ctx, block.Name, *c)
			issuerURL = c.IssuerURL
		case *config.StaticConfig:
			iss, err = NewStatic(block.Name, *c)
		case *config.GitHubOAuthConfig:
			iss, err = NewGitHubOAuthIssuer(block.Name, *c)
		case *config.TalmiSessionConfig:
			iss, err = NewTalmiSessionIssuer(block.Name, *c, signer)
		default:
			return nil, fmt.Errorf("unknown issuer config type for issuer %q", block.Name)
		}

		if err != nil {
			return nil, fmt.Errorf("building issuer %q: %w", block.Name, err)
		}

		issuers[block.Name] = iss
		if issuerURL != "" {
			urlMap[issuerURL] = block.Name
		}
	}

	return &Registry{
		issuers: issuers,
		urlMap:  urlMap,
	}, nil
}

func (r *Registry) findStaticIssuerByToken(token string) (string, *StaticIssuer, bool) {
	for k, iss := range r.issuers {
		if staticIss, ok := iss.(*StaticIssuer); ok {
			if _, ok := staticIss.tokenMap[token]; ok {
				return k, staticIss, true
			}
		}
	}
	return "", nil, false
}
