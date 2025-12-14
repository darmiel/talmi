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
	Type    string `yaml:"type"` // e.g., "file", "memory"
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

	seenRuleNames := make(map[string]struct{})
	for idx, rule := range c.Rules {
		if rule.Name == "" {
			return fmt.Errorf("rule at index %d has empty name", idx)
		}

		// validate unique rule names
		if _, exists := seenRuleNames[rule.Name]; exists {
			return fmt.Errorf("duplicate rule name found: '%s'", rule.Name)
		}
		seenRuleNames[rule.Name] = struct{}{}

		match := &rule.Match

		// validate issuer: it needs to be set and known
		if match.Issuer == "" {
			return fmt.Errorf("rule '%s' has empty match.issuer", rule.Name)
		}
		if _, ok := validIssuers[match.Issuer]; !ok {
			return fmt.Errorf("rule '%s' references unknown issuer '%s'", rule.Name, match.Issuer)
		}

		// validate conditions
		if match.Condition != nil && match.Expr != "" {
			return fmt.Errorf("rule '%s' has both match.condition and match.expr set; only one is allowed", rule.Name)
		}
		if match.Condition == nil && match.Expr == "" && !match.AllowEmptyCondition {
			return fmt.Errorf("rule '%s' has neither match.condition nor match.expr set, and allow_empty_condition is false", rule.Name)
		}
		if match.Expr != "" {
			out, err := expr.Compile(match.Expr, expr.AsBool())
			if err != nil {
				return fmt.Errorf("compiling expr for rule '%s': %w", rule.Name, err)
			}
			match.CompiledExpr = out
			c.Rules[idx] = rule
		}
		if match.Condition != nil {
			if err := match.Condition.Validate(); err != nil {
				return fmt.Errorf("validating condition for rule '%s': %w", rule.Name, err)
			}
		}

		// validate grant
		grant := &rule.Grant

		// validate grant provider: it needs to be set and known
		if grant.Provider == "" {
			return fmt.Errorf("rule '%s' has empty grant.provider", rule.Name)
		}
		if _, ok := validProviders[grant.Provider]; !ok {
			return fmt.Errorf("rule '%s' references unknown provider '%s'", rule.Name, grant.Provider)
		}

	}

	return nil
}
