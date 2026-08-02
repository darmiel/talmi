package api

import (
	"net/http"
	"strconv"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/darmiel/talmi/internal/api/presenter"
	"github.com/darmiel/talmi/internal/core"
)

// requireTalmi verifies the admin session and authorizes the principal for the given talmi resource/action.
// On failure, it writes the response and returns false.
func (s *Server) requireTalmi(
	w http.ResponseWriter,
	r *http.Request,
	resource core.Resource,
	action core.Action,
) (*core.Principal, bool) {
	token := bearerToken(r)
	if token == "" {
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
		log.Ctx(r.Context()).Error().Err(err).Msg("invalid session token")
		presenter.Error(w, r, "invalid session token", http.StatusUnauthorized)
		return nil, false
	}
	decision := s.admin.Authorize(principal, []core.ResourceRequest{
		{Resource: resource, Actions: []core.Action{action}},
	})
	if !decision.Authorized {
		presenter.Error(w, r, "not authorized for this action", http.StatusForbidden)
		return nil, false
	}
	return principal, true
}

func (s *Server) handleAuditQuery(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireTalmi(w, r, "talmi:audit", "read"); !ok {
		return
	}
	logger := log.Ctx(r.Context())

	q := r.URL.Query()
	filter := core.AuditFilter{
		CorrelationID: q.Get("correlation_id"),
		PrincipalID:   q.Get("principal_id"),
		Fingerprint:   q.Get("fingerprint"),
		Action:        q.Get("action"),
		Success:       parseBoolPtr(q.Get("success")),
		Since:         parseTime(q.Get("since")),
		Until:         parseTime(q.Get("until")),
		Limit:         parseLimit(q.Get("limit"), 50),
	}
	entries, err := s.admin.Auditor().Query(r.Context(), filter)
	if err != nil {
		logger.Error().Err(err).Msg("audit query failed")
		presenter.Error(w, r, "audit query failed", http.StatusInternalServerError)
		return
	}
	presenter.JSON(w, r, entries, http.StatusOK)
}

func (s *Server) handleListTasks(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireTalmi(w, r, "talmi:tasks", "read"); !ok {
		return
	}
	presenter.JSON(w, r, s.admin.Tasks.ListStatus(), http.StatusOK)
}

func (s *Server) handleTriggerTask(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if _, ok := s.requireTalmi(w, r, core.Resource("talmi:tasks/"+name), "trigger"); !ok {
		return
	}
	if err := s.admin.Tasks.Trigger(name); err != nil {
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

func parseBoolPtr(s string) *bool {
	switch s {
	case "true":
		b := true
		return &b
	case "false":
		b := false
		return &b
	default:
		return nil
	}
}

func parseTime(s string) time.Time {
	t, _ := time.Parse(time.RFC3339, s) // zero time on empty/invalid; filter ignores zero
	return t
}
