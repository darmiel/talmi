package config

import (
	"fmt"
	"os"

	"github.com/expr-lang/expr"
	"github.com/goccy/go-yaml"

	"github.com/darmiel/talmi/internal/core"
)

type Config struct {
	Issuers   []IssuerConfig   `yaml:"issuers"`
	Providers []ProviderConfig `yaml:"providers"`
	Rules     []core.Rule      `yaml:"rules"`
	Audit     AuditConfig      `yaml:"audit"`
}

// IssuerConfig holds configuration for an Identity Provider.
type IssuerConfig struct {
	Name   string         `yaml:"name"`
	Type   string         `yaml:"type"`    // e.g., "oidc", "static"
	Config map[string]any `yaml:",inline"` // Capture remaining fields
}

// ProviderConfig holds configuration for a Downstream Token Provider.
type ProviderConfig struct {
	Name   string         `yaml:"name"`
	Type   string         `yaml:"type"`    // e.g., "github_app", "stub"
	Config map[string]any `yaml:",inline"` // Capture remaining fields
}

// AuditConfig holds configuration for auditing.
type AuditConfig struct {
	Enabled bool   `yaml:"enabled"`
	Path    string `yaml:"path"`
}

// Load reads and parses the configuration file at the given path.
// It returns a Config struct or an error if loading/parsing/validation fails.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config file: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validating config file: %w", err)
	}
	return &cfg, nil
}

func (c *Config) Validate() error {
	validIssuers := make(map[string]struct{})
	for idx, i := range c.Issuers {
		if i.Name == "" {
			return fmt.Errorf("issuer at index %d has empty name", idx)
		}
		validIssuers[i.Name] = struct{}{}
	}

	validProviders := make(map[string]struct{})
	for idx, p := range c.Providers {
		if p.Name == "" {
			return fmt.Errorf("provider at index %d has empty name", idx)
		}
		validProviders[p.Name] = struct{}{}
	}

	// validate rules
	for idx, rule := range c.Rules {
		if rule.Name == "" {
			return fmt.Errorf("rule at index %d has empty name", idx)
		}

		// validate issuer: it needs to be set and known
		if rule.Match.Issuer == "" { // TODO: let's see for future if we want to allow empty issuer
			return fmt.Errorf("rule '%s' has empty match.issuer", rule.Name)
		}
		if _, ok := validIssuers[rule.Match.Issuer]; !ok {
			return fmt.Errorf("rule '%s' references unknown issuer '%s'", rule.Name, rule.Match.Issuer)
		}

		// validate grant provider: it needs to be set and known
		if rule.Grant.Provider == "" {
			return fmt.Errorf("rule '%s' has empty grant.provider", rule.Name)
		}
		if _, ok := validProviders[rule.Grant.Provider]; !ok {
			return fmt.Errorf("rule '%s' references unknown provider '%s'", rule.Name, rule.Grant.Provider)
		}

		// validate and compile expr
		if rule.Match.Expr != "" {
			out, err := expr.Compile(rule.Match.Expr, expr.AsBool())
			if err != nil {
				return fmt.Errorf("compiling expr for rule '%s': %w", rule.Name, err)
			}
			rule.Match.CompiledExpr = out
			c.Rules[idx] = rule
		}
	}

	return nil
}
