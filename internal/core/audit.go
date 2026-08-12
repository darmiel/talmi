package core

import (
	"context"
	"time"
)

// AuditAction is a typed event action.
type AuditAction string

const (
	ActionLeaseIssue      AuditAction = "lease.issue"
	ActionLeaseRevoke     AuditAction = "lease.revoke"
	ActionSessionLogin    AuditAction = "session.login"
	ActionConfigReload    AuditAction = "config.reload"
	ActionTaskTrigger     AuditAction = "task.trigger"
	ActionAuthzDenied     AuditAction = "authz.denied"
	ActionWebhookReceived AuditAction = "webhook.received"
)

// Outcome is the result of an audited action.
type Outcome string

const (
	OutcomeSuccess Outcome = "success"
	OutcomeFailure Outcome = "failure"
	OutcomeDenied  Outcome = "denied"
)

// Event is one audit record. The common fields apply to every action; Decision
// and Artifacts are populated only by lease events.
type Event struct {
	ID        string         `json:"id"`
	Time      time.Time      `json:"time"`
	Action    AuditAction    `json:"action"`
	Outcome   Outcome        `json:"outcome"`
	Actor     *Principal     `json:"actor,omitempty"`
	RequestID string         `json:"request_id,omitempty"`
	SessionID string         `json:"session_id,omitempty"`
	Revision  string         `json:"revision,omitempty"`
	Error     string         `json:"error,omitempty"`
	Metadata  map[string]any `json:"metadata,omitempty"`

	Decision  *Decision       `json:"decision,omitempty"`
	Artifacts []ArtifactAudit `json:"artifacts,omitempty"`
}

type ArtifactAudit struct {
	ArtifactID  string `json:"artifact_id"`
	Provider    string `json:"provider"`
	Fingerprint string `json:"fingerprint,omitempty"` // only some providers fingerprint tokens, e.g. GitHub
}

// AuditFilter selects audit entries by indexed criteria.
type AuditFilter struct {
	ID          string      `json:"id,omitempty"`
	RequestID   string      `json:"request_id,omitempty"`
	SessionID   string      `json:"session_id,omitempty"`
	ActorID     string      `json:"actor_id,omitempty"`
	Fingerprint string      `json:"fingerprint,omitempty"`
	Action      AuditAction `json:"action,omitempty"`
	Outcome     Outcome     `json:"outcome,omitempty"`
	Since       time.Time   `json:"since,omitzero"`
	Until       time.Time   `json:"until,omitzero"`
	Limit       int         `json:"limit,omitempty"` // 0 = no limit
}

// Auditor is append-only: Log writes, Query reads, Prune deletes only for
// retention. There is no update path.
type Auditor interface {
	Log(ctx context.Context, event Event) error
	Query(ctx context.Context, filter AuditFilter) ([]Event, error)
	Prune(ctx context.Context, before time.Time) (int, error)
	Close() error
}

//
//type AuditEntry struct {
//	// ID is the unique audit ID
//	ID string `json:"id"`
//
//	// Time is the timestamp of the event
//	Time time.Time `json:"time"`
//
//	// Action describing what happened (e.g. "token.mint", "auth.success")
//	Action string `json:"action"`
//
//	// Principal identifies who made the request
//	Principal *Principal `json:"principal"`
//
//	// RequestedProvider that was targeted
//	RequestedProvider string `json:"requested_provider,omitempty"`
//	// RequestedIssuer that was used
//	RequestedIssuer string `json:"issuer,omitempty"`
//
//	// Decision details
//	PolicyName string `json:"policy_name,omitempty"`
//	Provider   string `json:"provider,omitempty"`
//	Success    bool   `json:"success"`
//
//	// Revision is the policy revision that was used to make the decision
//	Revision string `json:"revision"`
//
//	// Artifacts contains the list of artifacts that were involved in the request
//	Artifacts []ArtifactAudit `json:"artifacts,omitempty"`
//
//	// Decision contains the per-request coverage tree
//	Decision *Decision `json:"decision,omitempty"`
//
//	// Error contains a summary of the error that occurred, if any.
//	// This is a high-level message suitable for logging and monitoring.
//	Error string `json:"error,omitempty"`
//	// Stacktrace contains the full error message.
//	Stacktrace string `json:"stacktrace,omitempty"` // more detailed error info
//
//	// Metadata contains artifact details
//	Metadata map[string]any `json:"metadata,omitempty"`
//}
//

//
//type Auditor interface {
//	Log(ctx context.Context, entry AuditEntry) error
//	Query(ctx context.Context, filter AuditFilter) ([]AuditEntry, error)
//	Close() error
//}
