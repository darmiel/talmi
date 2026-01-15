package api

import (
	"net/http"

	"github.com/darmiel/talmi/internal/api/presenter"
)

// handleListTasks responds with the list of tasks and their statuses.
func (s *Server) handleListTasks(w http.ResponseWriter, r *http.Request) {
	status := s.taskManager.ListStatus()
	presenter.JSON(w, r, status, http.StatusOK)
}

type TriggerTaskResponse struct {
	Status string `json:"status"`
}

// handleTriggerTask triggers a specific task by its ID.
func (s *Server) handleTriggerTask(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if name == "" {
		presenter.Error(w, r, "missing task name", http.StatusBadRequest)
		return
	}
	if err := s.taskManager.Trigger(name); err != nil {
		presenter.Error(w, r, err.Error(), http.StatusInternalServerError)
		return
	}
	presenter.JSON(w, r, TriggerTaskResponse{
		Status: "triggered",
	}, http.StatusOK)
}

// handleLogsForTask retrieves logs for a specific task.
func (s *Server) handleLogsForTask(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if name == "" {
		presenter.Error(w, r, "missing task name", http.StatusBadRequest)
	}
	logs, err := s.taskManager.GetLogs(name)
	if err != nil {
		presenter.Error(w, r, err.Error(), http.StatusInternalServerError)
		return
	}
	presenter.JSON(w, r, logs, http.StatusOK)
}
