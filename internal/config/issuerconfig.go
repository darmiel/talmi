package config

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/go-viper/mapstructure/v2"
)

const mapstructureTag = "mapstructure"

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

var issuerConfigTypes = map[string]func() IssuerConfig{
	"oidc":          func() IssuerConfig { return &OIDCConfig{} },
	"static":        func() IssuerConfig { return &StaticConfig{} },
	"github-oauth":  func() IssuerConfig { return &GitHubOAuthConfig{} },
	"talmi-session": func() IssuerConfig { return &TalmiSessionConfig{} },
}

func DecodeIssuerConfig(block IssuerBlock) (IssuerConfig, error) {
	newCfg, ok := issuerConfigTypes[block.Type]
	if !ok {
		return nil, fmt.Errorf("unknown issuer type: %q", block.Type)
	}
	target := newCfg()

	// The inline Config map also captures the block's own "name"/"type" keys;
	// drop them so strict decoding doesn't report them as unknown fields.
	raw := make(map[string]any, len(block.Config))
	for k, v := range block.Config {
		if k == "name" || k == "type" {
			continue
		}
		raw[k] = v
	}

	dec, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		Result:      target,
		ErrorUnused: true,
		TagName:     mapstructureTag,
	})
	if err != nil {
		return nil, fmt.Errorf("issuer decoder: %w", err)
	}
	if err := dec.Decode(raw); err != nil {
		return nil, fmt.Errorf("issuer %q (type %q): %w; valid keys: %s",
			block.Name, block.Type, err, strings.Join(knownIssuerKeys(target), ", "))
	}
	if err := target.Validate(); err != nil {
		return nil, err
	}
	return target, nil
}

func knownIssuerKeys(cfg IssuerConfig) []string {
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
