package core

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEventJSONRoundTrip(t *testing.T) {
	t.Parallel()
	is := assert.New(t)
	must := require.New(t)

	e := Event{
		ID:        "e1",
		Action:    ActionLeaseIssue,
		Outcome:   OutcomeSuccess,
		RequestID: "req1",
		SessionID: "sess1",
		Actor:     &Principal{ID: "svc"},
		Artifacts: []ArtifactAudit{{ArtifactID: "a1", Provider: "github"}},
	}

	b, err := json.Marshal(e)
	must.NoError(err)

	var got Event
	must.NoError(json.Unmarshal(b, &got))

	is.Equal(ActionLeaseIssue, got.Action)
	is.Equal(OutcomeSuccess, got.Outcome)
	is.Equal("req1", got.RequestID)
	is.Equal("sess1", got.SessionID)
	must.Len(got.Artifacts, 1)
	is.Equal("a1", got.Artifacts[0].ArtifactID)
}
