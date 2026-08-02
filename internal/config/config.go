package config

import (
	"time"

	"github.com/darmiel/talmi/internal/core"
	"github.com/darmiel/talmi/internal/secret"
)

// Config is the local bootstrap.
type Config struct {
	Grade        string        `yaml:"grade"`
	Signing      SigningConfig `yaml:"signing"`
	Store        StoreConfig   `yaml:"store"`
	Audit        AuditConfig   `yaml:"audit"`
	ConfigSource *SourceConfig `yaml:"configSource"`

	// Local sourced sections
	Issuers Includes `yaml:"issuers"`
	Realms  Includes `yaml:"realms"`
	Rules   Includes `yaml:"rules"`
}

type SigningConfig struct {
	Algorithm string     `yaml:"algorithm"` // ES256 / HS256
	Key       secret.Ref `yaml:"key"`
}

type StoreConfig struct {
	Type string     `yaml:"type"` // memory | postgres
	DSN  secret.Ref `yaml:"dsn,omitempty"`
}

type AuditConfig struct {
	Enabled bool   `yaml:"enabled"`
	Type    string `yaml:"type"` // jsonl | memory | noop // TODO update to postgres
	Path    string `yaml:"path,omitempty"`
}

// SourceConfig points at where the sourced tree lives
type SourceConfig struct {
	GitHub *GitHubSource `yaml:"github,omitempty"`
	Sync   SyncConfig    `yaml:"sync,omitempty"`
}

type GitHubSource struct {
	Server         string     `yaml:"server,omitempty"`
	Owner          string     `yaml:"owner"`
	Repo           string     `yaml:"repo"`
	Ref            string     `yaml:"ref"`
	Path           string     `yaml:"path"`
	AppID          int64      `yaml:"app_id"`
	InstallationID int64      `yaml:"installation_id,omitempty"`
	PrivateKey     secret.Ref `yaml:"private_key"`
	WebhookSecret  secret.Ref `yaml:"webhook_secret,omitempty"`
}

type SyncConfig struct {
	Interval time.Duration `yaml:"interval,omitempty"`
}

// Includes selects sectioned files by glob relative to the config base dir.
type Includes struct {
	Include []string `yaml:"include"`
}

// IssuerBlock is one issuer definition
type IssuerBlock struct {
	Name   string         `yaml:"name"`
	Type   string         `yaml:"type"` // oidc | static | github-oauth | talmi-session // TODO
	Config map[string]any `yaml:",inline"`
}

type RealmBlock struct {
	Realm      string          `yaml:"realm"`
	Type       string          `yaml:"type"` // github-app | artifactory | talmi
	Server     string          `yaml:"server,omitempty"`
	BaseURL    string          `yaml:"base_url,omitempty"`
	Capability CapabilityBlock `yaml:"capability,omitempty"`
	Instances  []InstanceBlock `yaml:"instances"`
}

type InstanceBlock struct {
	Name       string          `yaml:"name"`
	AppID      int64           `yaml:"app_id,omitempty"`
	PrivateKey secret.Ref      `yaml:"private_key,omitempty"`
	AdminToken secret.Ref      `yaml:"admin_token,omitempty"`
	Groups     []string        `yaml:"groups,omitempty"`     // artifactory
	Capability CapabilityBlock `yaml:"capability,omitempty"` // overrides realm-level
}

type CapabilityBlock struct {
	Discovery  string        `yaml:"discovery,omitempty"` // api | static
	Refresh    time.Duration `yaml:"refresh_interval,omitempty"`
	Resources  []string      `yaml:"resources,omitempty"`
	MaxActions []core.Action `yaml:"max_actions,omitempty"`
}

func (c CapabilityBlock) isSet() bool {
	return c.Discovery != "" || c.Refresh != 0 || len(c.Resources) > 0 || len(c.MaxActions) > 0
}

// SourcedConfig is the assembled issuers / realms / rules tree.
type SourcedConfig struct {
	Issuers []IssuerBlock
	Realms  []RealmBlock
	Rules   []core.Rule
}

//type Config struct {
//	Issuers      []IssuerConfig   `yaml:"issuers"`
//	Providers    []ProviderConfig `yaml:"providers"`
//	Rules        []core.Rule      `yaml:"rules"`
//	Audit        AuditConfig      `yaml:"audit"`
//	PolicySource *PolicySource    `yaml:"policy_source"`
//}
//
//type PolicySourceSync struct {
//	Interval time.Duration `yaml:"interval"`
//}
//
//type GitHubSourceConfig struct {
//	// AppID is the GitHub App ID.
//	AppID int64 `yaml:"app_id"`
//
//	// InstallationID is the GitHub App installation ID.
//	InstallationID int64 `yaml:"installation_id"`
//
//	// ServerURL is the GitHub Enterprise server URL.
//	// For GitHub.com, this can be left empty.
//	ServerURL string `yaml:"server"`
//
//	// PrivateKey is the GitHub App private key in PEM format.
//	PrivateKey string `yaml:"private_key"`
//
//	// Owner of the GitHub repository.
//	Owner string `yaml:"owner"`
//
//	// Repo is the name of the GitHub repository.
//	Repo string `yaml:"repo"`
//
//	// Path is the directory path within the repository to load policies from.
//	// For example, "policies/".
//	Path string `yaml:"path"`
//
//	// Ref is the git reference to use (e.g. a branch).
//	// For example, "main".
//	Ref string `yaml:"ref"`
//
//	// WebhookSecret is the secret used to validate GitHub webhooks.
//	WebhookSecret string `yaml:"webhook_secret"`
//}
//
//func (c *GitHubSourceConfig) Validate() error {
//	if c.AppID == 0 {
//		return fmt.Errorf("app_id is required")
//	}
//	if c.InstallationID == 0 {
//		return fmt.Errorf("installation_id is required")
//	}
//	if c.PrivateKey == "" {
//		return fmt.Errorf("private_key is required")
//	}
//	if c.Owner == "" {
//		return fmt.Errorf("owner is required")
//	}
//	if c.Repo == "" {
//		return fmt.Errorf("repo is required")
//	}
//	if c.Ref == "" {
//		return fmt.Errorf("ref is required")
//	}
//	return nil
//}
//
//// PolicySource holds configuration for the policy source => where to load policies from.
//type PolicySource struct {
//	// GitHub holds configuration for GitHub as a policy source.
//	GitHub *GitHubSourceConfig `yaml:"github,omitempty"`
//
//	Sync PolicySourceSync `yaml:"sync"`
//}
//
//func (s *PolicySource) Validate() error {
//	switch {
//	case s.GitHub != nil:
//		if err := s.GitHub.Validate(); err != nil {
//			return fmt.Errorf("validating GitHub policy source: %w", err)
//		}
//	default:
//		return fmt.Errorf("no valid policy source configured")
//	}
//	return nil
//}
//
//// IssuerConfig holds configuration for an Identity Provider.
//type IssuerConfig struct {
//	Name   string         `yaml:"name"`
//	Type   string         `yaml:"type"`    // e.g., "oidc", "static"
//	Config map[string]any `yaml:",inline"` // Capture remaining fields
//}
//
//// ProviderConfig holds configuration for a Downstream Token Provider.
//type ProviderConfig struct {
//	Name   string         `yaml:"name"`
//	Type   string         `yaml:"type"`    // e.g., "github_app", "stub"
//	Config map[string]any `yaml:",inline"` // Capture remaining fields
//}
//
//// AuditConfig holds configuration for auditing.
//type AuditConfig struct {
//	Enabled bool   `yaml:"enabled"`
//	Path    string `yaml:"path"`
//	Type    string `yaml:"type"` // e.g., "file", "memory"
//}
//
//// Load reads and parses the configuration file at the given path.
//// It returns a Config struct or an error if loading/parsing/validation fails.
//func Load(path string) (*Config, error) {
//	data, err := os.ReadFile(path)
//	if err != nil {
//		return nil, fmt.Errorf("reading config file: %w", err)
//	}
//	var cfg Config
//	if err := yaml.Unmarshal(data, &cfg); err != nil {
//		return nil, fmt.Errorf("parsing config file: %w", err)
//	}
//	if err := cfg.Validate(); err != nil {
//		return nil, fmt.Errorf("validating config file: %w", err)
//	}
//	return &cfg, nil
//}
//
//func (c *Config) Validate() error {
//	validIssuers := make(map[string]struct{})
//	for idx, i := range c.Issuers {
//		if i.Name == "" {
//			return fmt.Errorf("issuer at index %d has empty name", idx)
//		}
//		validIssuers[i.Name] = struct{}{}
//	}
//
//	validProviders := make(map[string]struct{})
//	for idx, p := range c.Providers {
//		if p.Name == "" {
//			return fmt.Errorf("provider at index %d has empty name", idx)
//		}
//		validProviders[p.Name] = struct{}{}
//	}
//
//	validRules, err := validation.ValidateRules(c.Rules, validIssuers, validProviders)
//	if err != nil {
//		return fmt.Errorf("validating rules: %w", err)
//	}
//	c.Rules = validRules
//
//	if c.PolicySource != nil {
//		if err := c.PolicySource.Validate(); err != nil {
//			return fmt.Errorf("validating policy source: %w", err)
//		}
//	}
//
//	return nil
//}
