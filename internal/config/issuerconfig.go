package config

import (
	"fmt"
	"reflect"
	"sort"
	"strings"

	"github.com/go-viper/mapstructure/v2"
)

const mapstructureTag = "mapstructure"

var issuerConfigTypes = map[string]func() IssuerConfig{
	IssuerTypeOIDC:         func() IssuerConfig { return &OIDCConfig{} },
	IssuerTypeStatic:       func() IssuerConfig { return &StaticConfig{} },
	IssuerTypeGitHubOAuth:  func() IssuerConfig { return &GitHubOAuthConfig{} },
	IssuerTypeTalmiSession: func() IssuerConfig { return &TalmiSessionConfig{} },
}

// IssuerTypes returns the known issuer types (sorted).
func IssuerTypes() []string {
	out := make([]string, 0, len(issuerConfigTypes))
	for t := range issuerConfigTypes {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// IssuerConfig is the decoded, typed configuration for one issuer.
type IssuerConfig interface {
	// Validate checks required fields / formats after decoding.
	Validate() error
}

type OIDCConfig struct {
	IssuerURL string `mapstructure:"issuer_url" json:"issuer_url" jsonschema:"required"`
	ClientID  string `mapstructure:"client_id" json:"client_id" jsonschema:"required"`
}

func (c OIDCConfig) Validate() error {
	if c.IssuerURL == "" {
		return fmt.Errorf("oidc issuer requires 'issuer_url'")
	}
	if c.ClientID == "" {
		return fmt.Errorf("oidc issuer requires 'client_id'")
	}
	return nil
}

type StaticConfig struct {
	TokenMap map[string]map[string]any `mapstructure:"token_map" json:"token_map,omitempty"`
}

func (StaticConfig) Validate() error {
	return nil // empty map is allowed
}

type GitHubOAuthConfig struct {
	Server string `mapstructure:"server" json:"server,omitempty"`
}

func (GitHubOAuthConfig) Validate() error {
	return nil // empty server is allowed, defaults to github.com
}

type TalmiSessionConfig struct{}

func (TalmiSessionConfig) Validate() error {
	return nil
}

func DecodeIssuerConfig(block IssuerBlock) (IssuerConfig, error) {
	newCfg, ok := issuerConfigTypes[block.Type]
	if !ok {
		return nil, fmt.Errorf("unknown issuer type: %q", block.Type)
	}
	target := newCfg()
	if err := strictDecode(block.Config, target); err != nil {
		return nil, fmt.Errorf("issuer %q (type %q): %w; valid keys: %s",
			block.Name, block.Type, err, strings.Join(knownMapstructureTags(target), ", "))
	}
	if err := target.Validate(); err != nil {
		return nil, err
	}
	return target, nil
}

// strictDecode decodes raw into target, rejecting unknown keys.
func strictDecode(raw map[string]any, target any) error {
	clean := make(map[string]any, len(raw))
	for k, v := range raw {
		if k == "name" || k == "type" {
			continue
		}
		clean[k] = v
	}
	dec, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		Result:      target,
		ErrorUnused: true,
		TagName:     mapstructureTag,
	})
	if err != nil {
		return fmt.Errorf("building decoder: %w", err)
	}
	return dec.Decode(clean)
}

func knownMapstructureTags(cfg any) []string {
	var keys []string
	rt := reflect.TypeOf(cfg)
	if rt.Kind() != reflect.Pointer {
		return nil
	}
	rt = rt.Elem()
	for i := 0; i < rt.NumField(); i++ {
		field := rt.Field(i)
		tag := field.Tag.Get(mapstructureTag)
		if tag != "" {
			keys = append(keys, tag)
		}
	}
	return keys
}
