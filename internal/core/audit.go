package core

import (
	"context"
	"time"
)

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
	Success    bool   `json:"success"`

	// Revision is the policy revision that was used to make the decision
	Revision string `json:"revision"`

	// Artifacts contains the list of artifacts that were involved in the request
	Artifacts []ArtifactAudit `json:"artifacts,omitempty"`

	// Decision contains the per-request coverage tree
	Decision *Decision `json:"decision,omitempty"`

	// Error contains a summary of the error that occurred, if any.
	// This is a high-level message suitable for logging and monitoring.
	Error string `json:"error,omitempty"`
	// Stacktrace contains the full error message.
	Stacktrace string `json:"stacktrace,omitempty"` // more detailed error info

	// Metadata contains artifact details
	Metadata map[string]any `json:"metadata,omitempty"`
}

type ArtifactAudit struct {
	ArtifactID  string `json:"artifact_id"`
	Provider    string `json:"provider"`
	Fingerprint string `json:"fingerprint,omitempty"` // only some providers fingerprint tokens, e.g. GitHub
}

// AuditFilter selects audit entries by indexed criteria.
type AuditFilter struct {
	CorrelationID string    `json:"correlation_id,omitempty"`
	PrincipalID   string    `json:"principal_id,omitempty"`
	Fingerprint   string    `json:"fingerprint,omitempty"`
	Action        string    `json:"action,omitempty"`
	Success       *bool     `json:"success,omitempty"`
	Since         time.Time `json:"since"`
	Until         time.Time `json:"until"`
	Limit         int       `json:"limit,omitempty"` // 0 = no limit
}

type Auditor interface {
	Log(ctx context.Context, entry AuditEntry) error
	Query(ctx context.Context, filter AuditFilter) ([]AuditEntry, error)
	Close() error
}
