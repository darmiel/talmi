package api

import (
	"net/http"

	"github.com/darmiel/talmi/internal/api/presenter"
	"github.com/darmiel/talmi/internal/buildinfo"
)

// handleHealth responds with a simple OK status to indicate the server is healthy.
func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("OK"))
}

// handleAbout responds with service information including version and commit hash.
func (s *Server) handleAbout(w http.ResponseWriter, r *http.Request) {
	presenter.JSON(w, r, buildinfo.GetBuildInfo(), http.StatusOK)
}
