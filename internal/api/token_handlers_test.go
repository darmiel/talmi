package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/darmiel/talmi/internal/core"
	"github.com/darmiel/talmi/internal/service"
)

type fakeService struct {
	issueResp  *service.IssueResponse
	issueErr   error
	revokeResp *service.RevokeResponse
	revokeErr  error
	gotIssue   service.IssueRequest
	gotRevoke  service.RevokeRequest
}

func (f *fakeService) IssueLease(_ context.Context, req service.IssueRequest) (*service.IssueResponse, error) {
	f.gotIssue = req
	return f.issueResp, f.issueErr
}

func (f *fakeService) RevokeLease(_ context.Context, req service.RevokeRequest) (*service.RevokeResponse, error) {
	f.gotRevoke = req
	return f.revokeResp, f.revokeErr
}

func (f *fakeService) Explain(_ context.Context, req service.IssueRequest) (*service.ExplainResponse, error) {
	return &service.ExplainResponse{}, nil
}

func do(t *testing.T, srv *Server, method, path, auth, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	if auth != "" {
		req.Header.Set("Authorization", "Bearer "+auth)
	}
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	return rec
}

func TestHandleIssue(t *testing.T) {
	t.Parallel()

	t.Run("success", func(t *testing.T) {
		t.Parallel()
		is := assert.New(t)
		fake := &fakeService{
			issueResp: &service.IssueResponse{
				LeaseID:          "l1",
				RevocationSecret: "sec",
				Artifacts: []service.IssuedArtifact{
					{
						Provider: "gh", Realm: "ghes-corp",
						Covers: []core.ResourceRequest{{Resource: "ghes-corp:acme/x"}},
						Token:  "tok-value", Fingerprint: "fp",
					},
				},
			},
		}
		srv := NewServer(func() TokenService {
			return fake
		})

		rec := do(t, srv, http.MethodPost, IssueTokenRoute, "oidc-jwt",
			`{"resources":[{"resource":"ghes-corp:acme/x","actions":["contents:read"]}]}`)

		require.Equal(t, http.StatusCreated, rec.Code)
		is.Equal("oidc-jwt", fake.gotIssue.Token)
		require.Len(t, fake.gotIssue.Resources, 1)
		is.Equal(core.Resource("ghes-corp:acme/x"), fake.gotIssue.Resources[0].Resource)

		var body issueResponseBody
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
		is.Equal("l1", body.LeaseID)
		is.Equal("sec", body.RevocationSecret)
		require.Len(t, body.Artifacts, 1)
		is.Equal("tok-value", body.Artifacts[0].Token)
		is.Equal([]string{"ghes-corp:acme/x"}, body.Artifacts[0].Covers)
	})

	t.Run("missing auth", func(t *testing.T) {
		t.Parallel()
		rec := do(t, NewServer(func() TokenService {
			return &fakeService{}
		}), http.MethodPost, IssueTokenRoute, "",
			`{"resources":[{"resource":"r:x","actions":["a"]}]}`)
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	t.Run("empty resources", func(t *testing.T) {
		t.Parallel()
		rec := do(t, NewServer(func() TokenService {
			return &fakeService{}
		}), http.MethodPost, IssueTokenRoute, "jwt", `{"resources":[]}`)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("bad json", func(t *testing.T) {
		t.Parallel()
		rec := do(t, NewServer(func() TokenService {
			return &fakeService{}
		}), http.MethodPost, IssueTokenRoute, "jwt", `{bad`)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("service error maps status", func(t *testing.T) {
		t.Parallel()
		fake := &fakeService{
			issueErr: service.HTTPError{
				StatusCode: http.StatusForbidden,
				Wrapped:    errors.New("policy denied"),
			},
		}
		rec := do(t, NewServer(func() TokenService {
			return fake
		}), http.MethodPost, IssueTokenRoute, "jwt",
			`{"resources":[{"resource":"r:x","actions":["a"]}]}`)
		assert.Equal(t, http.StatusForbidden, rec.Code)
	})
}

func TestHandleRevoke(t *testing.T) {
	t.Parallel()

	t.Run("success", func(t *testing.T) {
		t.Parallel()
		is := assert.New(t)
		fake := &fakeService{revokeResp: &service.RevokeResponse{LeaseID: "l1", Revoked: []string{"fp"}}}
		srv := NewServer(func() TokenService {
			return fake
		})

		rec := do(t, srv, http.MethodPost, RevokeTokenRoute, "the-secret", `{"tokens":{"fp":"tok"}}`)
		require.Equal(t, http.StatusOK, rec.Code)
		is.Equal("the-secret", fake.gotRevoke.RevocationSecret)
		is.Equal("tok", fake.gotRevoke.Tokens["fp"])
	})

	t.Run("missing secret", func(t *testing.T) {
		t.Parallel()
		rec := do(t, NewServer(func() TokenService {
			return &fakeService{}
		}), http.MethodPost, RevokeTokenRoute, "", `{}`)
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})
}
