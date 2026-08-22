package config

import (
	"fmt"
	"time"

	"github.com/darmiel/talmi/internal/core"
	"github.com/darmiel/talmi/internal/secret"
)

var ErrInvalidConfigType = fmt.Errorf("invalid config type")

// Config is the local bootstrap.
type Config struct {
	Grade        string           `yaml:"grade"`
	Signing      SigningConfig    `yaml:"signing"`
	Store        StoreConfig      `yaml:"store"`
	Audit        AuditConfig      `yaml:"audit"`
	ConfigSource *SourceConfig    `yaml:"source"`
	Auth         *AuthConfig      `yaml:"auth,omitempty"`
	RateLimit    *RateLimitConfig `yaml:"rate_limit,omitempty"`

	// NodeID is a stable identifier for this node, used in distributed locking and audit.
	// If empty, will use the hostname.
	NodeID string `yaml:"node_id,omitempty"`

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
	Type           string        `yaml:"type"` // memory | postgres
	DSN            secret.Ref    `yaml:"dsn,omitempty"`
	ConnectTimeout time.Duration `yaml:"connect_timeout,omitempty"` // 0 = default (10s)
}

type AuditConfig struct {
	Enabled        bool          `yaml:"enabled"`
	Type           string        `yaml:"type"` // postgres | memory | noop
	DSN            secret.Ref    `yaml:"dsn,omitempty"`
	Retention      time.Duration `yaml:"retention,omitempty"`
	Sinks          []string      `yaml:"sinks,omitempty"`
	ConnectTimeout time.Duration `yaml:"connect_timeout,omitempty"` // 0 = default (10s)
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
	Type   string         `yaml:"type"`
	Config map[string]any `yaml:",inline"`
}

type RealmBlock struct {
	Realm      string          `yaml:"realm"`
	Type       string          `yaml:"type"` // github-app | artifactory | talmi
	Capability CapabilityBlock `yaml:"capability,omitempty"`
	Instances  []InstanceBlock `yaml:"instances"`
}

type InstanceBlock struct {
	Name       string          `yaml:"name"`
	Capability CapabilityBlock `yaml:"capability,omitempty"` // overrides realm-level
	Config     map[string]any  `yaml:",inline"`
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

// AuthConfig is the configuration for authentication (admin API access).
type AuthConfig struct {
	LoginIssuer   string        `yaml:"login_issuer"`   // github-oauth issuer name
	SessionIssuer string        `yaml:"session_issuer"` // talmi-session issuer name
	SessionTTL    time.Duration `yaml:"session_ttl"`
	Server        string        `yaml:"server"`    // GHES base
	ClientID      string        `yaml:"client_id"` // GHES oauth app client ID
	Scopes        []string      `yaml:"scopes"`
}

// RateLimitConfig configures the two-layer request limiter.
type RateLimitConfig struct {
	Enabled        bool                      `yaml:"enabled"`
	Backend        string                    `yaml:"backend"` // memory | redis; "" = memory
	Redis          RedisConfig               `yaml:"redis,omitempty"`
	TrustedProxies []string                  `yaml:"trusted_proxies,omitempty"` // peers whose XFF we trust
	BypassCIDRs    []string                  `yaml:"bypass_cidrs,omitempty"`    // callers that skip limiting
	IP             RateLimitProfile          `yaml:"ip"`
	Principal      RateLimitProfile          `yaml:"principal"`
	Costs          map[string]map[string]int `yaml:"costs,omitempty"` // category -> class -> cost override
}

type RedisConfig struct {
	Addr     string     `yaml:"addr,omitempty"`
	Password secret.Ref `yaml:"password,omitempty"`
	DB       int        `yaml:"db,omitempty"`
}

// RateLimitProfile is the bucket shape for one layer.
type RateLimitProfile struct {
	Capacity     int     `yaml:"capacity"`
	RefillPerSec float64 `yaml:"refill_per_sec"`
}
