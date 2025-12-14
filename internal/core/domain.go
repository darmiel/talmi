package core

import (
	"time"

	"github.com/expr-lang/expr/vm"
)

// Principal represents the authenticated identity of the caller.
// It is produced by an Issuer after verifying an upstream token.
type Principal struct {
	// ID is the unique subject identifier (e.g., email, sub claim).
	ID string
	// Issuer is the name of the trusted issuer that verified this principal.
	Issuer string
	// Attributes are the claims extracted from the upstream token.
	Attributes map[string]any
}

// Grant describes exactly what access is allowed if a rule matches.
type Grant struct {
	// Provider is the name of the downstream provider (defined in config)
	// that will mint the token.
	Provider string `yaml:"provider" json:"provider"`

	// Permissions is a flexible map of permissions to grant.
	// Interpretation depends on the Provider (e.g. "contents": "read").
	Permissions map[string]string `yaml:"permissions" json:"permissions"`

	// Config allows arbitrary provider-specific configuration in the rule.
	// This supports, for example, defining `"repositories": ["a", "b"]` for GitHub.
	Config map[string]any `yaml:"config" json:"config"`
}

// Match defines the conditions required for a Rule to apply.
type Match struct {
	// Issuer is the name of the issuer that must have produced the Principal.
	Issuer string `yaml:"issuer" json:"issuer"`

	// Conditions is a list of additional conditions that must all be satisfied.
	// Leaving this empty means no condition-based restriction.
	Conditions []Condition `yaml:"conditions" json:"conditions"`

	// Expr is an optional expression for more complex matching logic.
	// Leaving this empty means no expression-based restriction.
	Expr string `yaml:"expr" json:"expr"`

	// CompiledExpr holds the pre-compiled form of Expr for efficient evaluation.
	CompiledExpr *vm.Program `yaml:"-" json:"-"`
}

// Rule binds a Match condition to a Grant action.
type Rule struct {
	// Name is a human-readable identifier for logs/debugging.
	Name string `yaml:"name" json:"name"`

	// Description explains the intent of the rule.
	Description string `yaml:"description" json:"description"`

	// Match defines criteria for the Principal.
	Match Match `yaml:"match" json:"match"`

	// Grant defines what is given if the match succeeds.
	Grant Grant `yaml:"grant" json:"grant"`
}

// TokenArtifact is the result of a successful Mint operation.
type TokenArtifact struct {
	// Value is the actual secret/token string (e.g., the GitHub Installation Token).
	Value string `json:"value"`

	// ExpiresAt indicates when this token becomes invalid.
	ExpiresAt time.Time `json:"expires_at"`

	// Metadata contains extra information (e.g., "git_user": "x-access-token").
	Metadata map[string]any `json:"metadata,omitempty"`
}
