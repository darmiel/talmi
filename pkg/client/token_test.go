package client

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIssueLeaseSendsBearerAndBody(t *testing.T) {
	t.Parallel()
	var gotAuth string
	var gotBody IssueRequestBody
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &gotBody)
		_ = json.NewEncoder(w).Encode(IssueResponse{
			LeaseID:   "l1",
			Artifacts: []IssuedArtifact{{Provider: "gh", Token: "tok"}},
		})
	}))
	defer srv.Close()

	resp, _, err := New(srv.URL).IssueLease(context.Background(), "oidc-jwt", IssueRequestBody{
		Resources: []ResourceRequest{{Resource: "ghes-corp:acme/x", Actions: []string{"contents:read"}}},
	})
	require.NoError(t, err)
	assert.Equal(t, "Bearer oidc-jwt", gotAuth)
	assert.Equal(t, "ghes-corp:acme/x", gotBody.Resources[0].Resource)
	assert.Equal(t, "l1", resp.LeaseID)
	assert.Equal(t, "tok", resp.Artifacts[0].Token)
}
