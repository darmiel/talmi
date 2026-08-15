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
