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

	// RequestedProvider that was targeted
	RequestedProvider string `json:"requested_provider,omitempty"`
	// RequestedIssuer that was used
	RequestedIssuer string `json:"issuer,omitempty"`

	// Decision details
	PolicyName string `json:"policy_name,omitempty"`
	Provider   string `json:"provider,omitempty"`
	Granted    bool   `json:"granted"`
	Error      string `json:"error,omitempty"`

	// Metadata contains artifact details
	Metadata map[string]any `json:"metadata,omitempty"`
}

type Auditor interface {
	Log(entry AuditEntry) error
	Close() error
}
