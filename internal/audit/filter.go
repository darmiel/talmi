package audit

import (
	"slices"

	"github.com/darmiel/talmi/internal/core"
)

func matchFilter(e core.Event, f core.AuditFilter) bool {
	switch {
	case f.ID != "" && e.ID != f.ID:
		return false
	case f.Action != "" && e.Action != f.Action:
		return false
	case f.Outcome != "" && e.Outcome != f.Outcome:
		return false
	case f.RequestID != "" && e.RequestID != f.RequestID:
		return false
	case f.SessionID != "" && e.SessionID != f.SessionID:
		return false
	case f.ActorID != "" && (e.Actor == nil || e.Actor.ID != f.ActorID):
		return false
	case f.Fingerprint != "" && !slices.ContainsFunc(e.Artifacts, func(a core.ArtifactAudit) bool {
		return a.Fingerprint == f.Fingerprint
	}):
		return false
	case !f.Since.IsZero() && e.Time.Before(f.Since):
		return false
	case !f.Until.IsZero() && e.Time.After(f.Until):
		return false
	}
	return true
}

// limitTail returns the last `limit` events from `events`.
func limitTail(events []core.Event, limit int) []core.Event {
	if limit > 0 && len(events) > limit {
		return events[len(events)-limit:]
	}
	return events
}
