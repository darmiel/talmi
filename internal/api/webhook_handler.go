package api

import (
	"net/http"
	"strings"

	"github.com/google/go-github/v80/github"
	"github.com/rs/zerolog/log"

	"github.com/darmiel/talmi/internal/api/presenter"
)

func (s *Server) handleGitHubWebhook(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := log.Ctx(ctx)

	if s.config.PolicySource == nil || s.config.PolicySource.GitHub == nil || s.config.PolicySource.GitHub.WebhookSecret == "" {
		logger.Warn().Msg("received GitHub webhook but no GitHub policy source is configured")
		presenter.Error(w, r, "webhooks not configured", http.StatusNotImplemented)
		return
	}

	signature := r.Header.Get(github.SHA256SignatureHeader)
	if signature == "" {
		signature = r.Header.Get(github.SHA1SignatureHeader)
	}

	payload, err := github.ValidatePayload(r, []byte(s.config.PolicySource.GitHub.WebhookSecret))
	if err != nil {
		logger.Warn().Err(err).Msg("invalid GitHub webhook payload")
		presenter.Error(w, r, "invalid payload", http.StatusUnauthorized)
		return
	}

	event, err := github.ParseWebHook(github.WebHookType(r), payload)
	if err != nil {
		logger.Warn().Err(err).Msg("failed to parse GitHub webhook")
		presenter.Error(w, r, "invalid webhook", http.StatusBadRequest)
		return
	}

	switch e := event.(type) {
	case *github.PushEvent:
		targetBranch := s.config.PolicySource.GitHub.Ref
		if targetBranch == "" {
			targetBranch = "main"
		}

		ref := e.GetRef()
		if !strings.HasSuffix(ref, "/"+targetBranch) {
			logger.Debug().
				Str("ref", ref).
				Str("target", targetBranch).
				Msg("ignoring push to non-target branch")
			presenter.JSON(w, r, map[string]string{
				"status": "ignored",
				"reason": "branch mismatch",
			}, http.StatusOK)
			return
		}

		logger.Info().
			Str("pusher", e.GetPusher().GetName()).
			Str("commit", e.GetHeadCommit().GetID()).
			Msg("retrieved valid push event, triggering policy sync")

		if err := s.taskManager.Trigger("git-sync"); err != nil {
			logger.Error().Err(err).Msg("failed to trigger sync task")
			presenter.Error(w, r, "failed to trigger sync", http.StatusInternalServerError)
			return
		}

		presenter.JSON(w, r, map[string]string{
			"status": "triggered",
			"task":   "git-sync", // TODO(future): use constant
			"commit": e.GetHeadCommit().GetID(),
		}, http.StatusOK)

	case *github.PingEvent:
		presenter.JSON(w, r, map[string]string{"status": "pong"}, http.StatusOK)

	default:
		presenter.JSON(w, r, map[string]string{"status": "ignored"}, http.StatusOK)
	}
}
