package api

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/darmiel/talmi/internal/api/presenter"
	"github.com/darmiel/talmi/internal/audit"
	"github.com/darmiel/talmi/internal/core"
	"github.com/darmiel/talmi/internal/correlation"
)

// requireTalmi verifies the admin session and authorizes the principal for the given talmi resource/action.
// On failure, it writes the response and returns false.
func (s *Server) requireTalmi(
	w http.ResponseWriter,
	r *http.Request,
	resource core.Resource,
	action core.Action,
) (*core.Principal, bool) {
	meta := map[string]any{"resource": string(resource), "action": string(action)}
	token := bearerToken(r)
	if token == "" {
		s.record(r.Context(), core.ActionAuthzDenied, core.OutcomeDenied,
			audit.WithError(fmt.Errorf("missing session token")), audit.WithMetadata(meta))
		presenter.Error(w, r, "missing session token", http.StatusUnauthorized)
		return nil, false
	}
	issuer, ok := s.admin.SessionIssuer()
	if !ok {
		presenter.Error(w, r, "session issuer not configured", http.StatusInternalServerError)
		return nil, false
	}
	principal, err := issuer.Verify(r.Context(), token)
	if err != nil {
		log.Ctx(r.Context()).Warn().Err(err).Msg("admin: invalid session token")
		s.record(r.Context(), core.ActionAuthzDenied, core.OutcomeDenied,
			audit.WithError(err), audit.WithMetadata(meta))
		presenter.Error(w, r, "invalid session token", http.StatusUnauthorized)
		return nil, false
	}
	decision := s.admin.Authorize(principal, []core.ResourceRequest{
		{Resource: resource, Actions: []core.Action{action}},
	})
	if !decision.Authorized {
		log.Ctx(r.Context()).Warn().
			Str("sub", principal.ID).
			Str("resource", string(resource)).
			Str("action", string(action)).
			Msg("admin: principal not authorized for action")
		s.record(withSession(r.Context(), principal), core.ActionAuthzDenied, core.OutcomeDenied,
			audit.WithActor(principal), audit.WithMetadata(meta))
		presenter.Error(w, r, "not authorized for this action", http.StatusForbidden)
		return nil, false
	}
	log.Ctx(r.Context()).Debug().
		Str("sub", principal.ID).
		Str("resource", string(resource)).
		Str("action", string(action)).
		Msg("admin: action authorized")
	return principal, true
}

// withSession attaches the principal's session id (jti) to the context so
// recorded events are linked to the login session.
func withSession(ctx context.Context, p *core.Principal) context.Context {
	if p == nil {
		return ctx
	}
	if sid, ok := p.Attributes["session_id"].(string); ok && sid != "" {
		return correlation.WithSession(ctx, sid)
	}
	return ctx
}

func (s *Server) handleAuditQuery(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireTalmi(w, r, "talmi:audit", "read"); !ok {
		return
	}
	logger := log.Ctx(r.Context())

	entries, err := s.admin.Auditor().Query(r.Context(), parseAuditFilter(r.URL.Query()))
	if err != nil {
		logger.Error().Err(err).Msg("audit query failed")
		presenter.Error(w, r, "audit query failed", http.StatusInternalServerError)
		return
	}
	presenter.JSON(w, r, entries, http.StatusOK)
}

func (s *Server) handleAuditEntry(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireTalmi(w, r, "talmi:audit", "read"); !ok {
		return
	}
	logger := log.Ctx(r.Context())
	id := r.PathValue("id")

	events, err := s.admin.Auditor().Query(r.Context(), core.AuditFilter{ID: id, Limit: 1})
	if err != nil {
		logger.Error().Err(err).Msg("audit entry lookup failed")
		presenter.Error(w, r, "audit query failed", http.StatusInternalServerError)
		return
	}
	if len(events) == 0 {
		presenter.Error(w, r, "audit entry not found", http.StatusNotFound)
		return
	}
	presenter.JSON(w, r, events[0], http.StatusOK)
}

func parseAuditFilter(q url.Values) core.AuditFilter {
	return core.AuditFilter{
		ID:          q.Get("id"),
		RequestID:   q.Get("request_id"),
		SessionID:   q.Get("session_id"),
		ActorID:     q.Get("principal_id"),
		Action:      core.AuditAction(q.Get("action")),
		Outcome:     core.Outcome(q.Get("outcome")),
		Fingerprint: q.Get("fingerprint"),
		Since:       parseTime(q.Get("since")),
		Until:       parseTime(q.Get("until")),
		Limit:       parseLimit(q.Get("limit"), 50),
	}
}

func (s *Server) handleListTasks(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireTalmi(w, r, "talmi:tasks", "read"); !ok {
		return
	}
	presenter.JSON(w, r, s.admin.Tasks.ListStatus(), http.StatusOK)
}

func (s *Server) handleTriggerTask(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	principal, ok := s.requireTalmi(w, r, core.Resource("talmi:tasks/"+name), "trigger")
	if !ok {
		return
	}
	ctx := withSession(r.Context(), principal)
	err := s.admin.Tasks.Trigger(name)
	outcome := core.OutcomeSuccess
	if err != nil {
		outcome = core.OutcomeFailure
	}
	s.record(ctx, core.ActionTaskTrigger, outcome,
		audit.WithActor(principal),
		audit.WithError(err),
		audit.WithMetadata(map[string]any{"task": name}))
	if err != nil {
		presenter.Error(w, r, "failed to trigger task: "+err.Error(), http.StatusNotFound)
		return
	}
	presenter.JSON(w, r, map[string]string{"status": "triggered", "task": name}, http.StatusAccepted)
}

func (s *Server) handleTaskLogs(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if _, ok := s.requireTalmi(w, r, core.Resource("talmi:tasks/"+name), "read"); !ok {
		return
	}
	logs, err := s.admin.Tasks.GetLogs(name)
	if err != nil {
		presenter.Error(w, r, "failed to get task logs: "+err.Error(), http.StatusInternalServerError)
		return
	}
	presenter.JSON(w, r, logs, http.StatusOK)
}

func parseLimit(s string, def int) int {
	if s == "" {
		return def
	}
	if n, err := strconv.Atoi(s); err == nil && n >= 0 {
		return n
	}
	return def
}

func parseTime(s string) time.Time {
	t, _ := time.Parse(time.RFC3339, s) // zero time on empty/invalid; filter ignores zero
	return t
}
