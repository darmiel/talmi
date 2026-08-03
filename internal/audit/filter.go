package audit

import (
	"slices"

	"github.com/darmiel/talmi/internal/core"
)

func matchFilter(e core.AuditEntry, f core.AuditFilter) bool {
	switch {
	case f.CorrelationID != "" && e.ID != f.CorrelationID:
		return false
	case f.Action != "" && e.Action != f.Action:
		return false
	case f.PrincipalID != "" && (e.Principal == nil || e.Principal.ID != f.PrincipalID):
		return false
	case f.Fingerprint != "" && !slices.ContainsFunc(e.Artifacts, func(audit core.ArtifactAudit) bool {
		return audit.Fingerprint == f.Fingerprint
	}):
		return false
	case f.Success != nil && e.Success != *f.Success:
		return false
	case !f.Since.IsZero() && e.Time.Before(f.Since):
		return false
	case !f.Until.IsZero() && e.Time.After(f.Until):
		return false
	}
	return true
}

// limitTail returns the last `limit` entries from `entries`.
func limitTail(entries []core.AuditEntry, limit int) []core.AuditEntry {
	if limit > 0 && len(entries) > limit {
		return entries[len(entries)-limit:]
	}
	return entries
}
