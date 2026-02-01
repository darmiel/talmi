package core

import "time"

type AuditEntry struct {
	// ID is the unique request ID (X-Correlation-ID)
	ID string `json:"id"`

	// Time is the timestamp of the event
	Time time.Time `json:"time"`

	// Action describing what happened (e.g. "token.mint", "auth.success")
	Action string `json:"action"`

	// Principal identifies who made the request
	Principal *Principal `json:"principal"`

	// RequestedIssuer that was used
	RequestedIssuer string `json:"requested_issuer,omitempty"`
	// RequestedTargets that were requested
	RequestedTargets []Target `json:"requested_targets,omitempty"`

	// Decision details
	PolicyName       string `json:"policy_name,omitempty"`
	Provider         string `json:"provider,omitempty"`
	Success          bool   `json:"success"`
	TokenFingerprint string `json:"token_fingerprint,omitempty"`

	Error      string `json:"error,omitempty"`
	Stacktrace string `json:"stacktrace,omitempty"` // more detailed error info

	// Metadata contains artifact details
	Metadata map[string]any `json:"metadata,omitempty"`
}

type Auditor interface {
	Log(entry AuditEntry) error
	GetRecent(limit int) ([]AuditEntry, error)
	Find(filter func(entry AuditEntry) bool, limit int) ([]AuditEntry, error)
	Close() error
}
