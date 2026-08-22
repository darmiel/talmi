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
	NodeID    string         `json:"node_id,omitempty"`
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
	NodeID      string      `json:"node_id,omitempty"`
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
