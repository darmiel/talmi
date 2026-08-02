package api

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func sign(secret, body []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func TestValidGitHubSignature(t *testing.T) {
	t.Parallel()
	secret := []byte("webhook-secret")
	body := []byte(`{"ref":"main"}`)

	assert.True(t, validGitHubSignature(secret, body, sign(secret, body)))
	assert.False(t, validGitHubSignature(secret, body, sign([]byte("wrong"), body)))
	assert.False(t, validGitHubSignature(secret, body, "no-prefix"))
	assert.False(t, validGitHubSignature(secret, body, "sha256=zzzz"))
	assert.False(t, validGitHubSignature(nil, body, sign(secret, body)))
}

func postWebhook(t *testing.T, srv *Server, secret, body []byte, validSig bool) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, WebhookGitHubRoute, bytes.NewReader(body))
	sig := sign(secret, body)
	if !validSig {
		sig = sign([]byte("wrong"), body)
	}
	req.Header.Set("X-Hub-Signature-256", sig)
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	return rec
}

func TestHandleWebhook(t *testing.T) {
	t.Parallel()
	secret := []byte("s")
	body := []byte(`{"ref":"main"}`)
	noSvc := func() TokenService { return nil }

	t.Run("valid signature triggers onWebhook", func(t *testing.T) {
		t.Parallel()
		called := false
		srv := NewServer(noSvc, WithGitHubWebhook(secret, func(context.Context) error { called = true; return nil }))
		rec := postWebhook(t, srv, secret, body, true)
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.True(t, called)
	})

	t.Run("invalid signature is rejected", func(t *testing.T) {
		t.Parallel()
		called := false
		srv := NewServer(noSvc, WithGitHubWebhook(secret, func(context.Context) error { called = true; return nil }))
		rec := postWebhook(t, srv, secret, body, false)
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
		assert.False(t, called)
	})

	t.Run("onWebhook error is 500", func(t *testing.T) {
		t.Parallel()
		srv := NewServer(noSvc, WithGitHubWebhook(secret, func(context.Context) error { return errors.New("boom") }))
		rec := postWebhook(t, srv, secret, body, true)
		assert.Equal(t, http.StatusInternalServerError, rec.Code)
	})

	t.Run("webhook route absent when not configured", func(t *testing.T) {
		t.Parallel()
		srv := NewServer(noSvc) // no WithWebhook
		rec := postWebhook(t, srv, secret, body, true)
		assert.Equal(t, http.StatusNotFound, rec.Code)
	})
}
