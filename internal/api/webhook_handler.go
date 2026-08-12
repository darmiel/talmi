package api

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"strings"

	"github.com/rs/zerolog/log"

	"github.com/darmiel/talmi/internal/api/presenter"
	"github.com/darmiel/talmi/internal/audit"
	"github.com/darmiel/talmi/internal/core"
)

func (s *Server) handleGitHubWebhook(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := log.Ctx(ctx)

	reader := http.MaxBytesReader(w, r.Body, 1<<20)
	defer func(reader io.ReadCloser) {
		_ = reader.Close()
	}(reader)
	body, err := io.ReadAll(reader)
	if err != nil {
		presenter.Error(w, r, "reading body failed", http.StatusBadRequest)
	}

	if !validGitHubSignature(s.gitHubWebhookSecret, body, r.Header.Get("X-Hub-Signature-256")) {
		presenter.Error(w, r, "invalid signature", http.StatusUnauthorized)
		return
	}

	if err := s.gitHubOnWebhook(ctx); err != nil {
		logger.Error().Err(err).Msg("webhook handler failed")
		s.record(ctx, core.ActionWebhookReceived, core.OutcomeFailure, audit.WithError(err))
		presenter.Error(w, r, "webhook handler failed", http.StatusInternalServerError)
		return
	}

	s.record(ctx, core.ActionWebhookReceived, core.OutcomeSuccess)
	presenter.JSON(w, r, map[string]string{"status": "ok"}, http.StatusOK)
}

// validGitHubSignature verifies GitHub's X-Hub-Signature-256 header against the request body using the provided secret.
func validGitHubSignature(secret, body []byte, header string) bool {
	if len(secret) == 0 {
		return false
	}
	const prefix = "sha256="
	if !strings.HasPrefix(header, prefix) {
		return false
	}
	want, err := hex.DecodeString(strings.TrimPrefix(header, prefix))
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	return hmac.Equal(mac.Sum(nil), want)
}

//
//	if s.config.PolicySource == nil || s.config.PolicySource.GitHub == nil || s.config.PolicySource.GitHub.WebhookSecret == "" {
//		logger.Warn().Msg("received GitHub webhook but no GitHub policy source is configured")
//		presenter.Error(w, r, "webhooks not configured", http.StatusNotImplemented)
//		return
//	}
//
//	signature := r.Header.Get(github.SHA256SignatureHeader)
//	if signature == "" {
//		signature = r.Header.Get(github.SHA1SignatureHeader)
//	}
//
//	payload, err := github.ValidatePayload(r, []byte(s.config.PolicySource.GitHub.WebhookSecret))
//	if err != nil {
//		logger.Warn().Err(err).Msg("invalid GitHub webhook payload")
//		presenter.Error(w, r, "invalid payload", http.StatusUnauthorized)
//		return
//	}
//
//	event, err := github.ParseWebHook(github.WebHookType(r), payload)
//	if err != nil {
//		logger.Warn().Err(err).Msg("failed to parse GitHub webhook")
//		presenter.Error(w, r, "invalid webhook", http.StatusBadRequest)
//		return
//	}
//
//	switch e := event.(type) {
//	case *github.PushEvent:
//		targetBranch := s.config.PolicySource.GitHub.Ref
//		if targetBranch == "" {
//			targetBranch = "main"
//		}
//
//		ref := e.GetRef()
//		if !strings.HasSuffix(ref, "/"+targetBranch) {
//			logger.Debug().
//				Str("ref", ref).
//				Str("target", targetBranch).
//				Msg("ignoring push to non-target branch")
//			presenter.JSON(w, r, map[string]string{
//				"status": "ignored",
//				"reason": "branch mismatch",
//			}, http.StatusOK)
//			return
//		}
//
//		logger.Info().
//			Str("pusher", e.GetPusher().GetName()).
//			Str("commit", e.GetHeadCommit().GetID()).
//			Msg("retrieved valid push event, triggering policy sync")
//
//		if err := s.taskManager.Trigger("git-sync"); err != nil {
//			logger.Error().Err(err).Msg("failed to trigger sync task")
//			presenter.Error(w, r, "failed to trigger sync", http.StatusInternalServerError)
//			return
//		}
//
//		presenter.JSON(w, r, map[string]string{
//			"status": "triggered",
//			"task":   "git-sync", // TODO(future): use constant
//			"commit": e.GetHeadCommit().GetID(),
//		}, http.StatusOK)
//
//	case *github.PingEvent:
//		presenter.JSON(w, r, map[string]string{"status": "pong"}, http.StatusOK)
//
//	default:
//		presenter.JSON(w, r, map[string]string{"status": "ignored"}, http.StatusOK)
//	}
//}
