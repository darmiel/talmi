package audit

import (
	"slices"

	"github.com/darmiel/talmi/internal/core"
)

func matchFilter(e core.Event, f core.AuditFilter) bool {
	for _, p := range []struct{ want, got string }{
		{f.ID, e.ID},
		{string(f.Action), string(e.Action)},
		{string(f.Outcome), string(e.Outcome)},
		{f.RequestID, e.RequestID},
		{f.SessionID, e.SessionID},
		{f.NodeID, e.NodeID},
	} {
		if p.want != "" && p.got != p.want {
			return false
		}
	}
	switch {
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
