package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/darmiel/talmi/internal/core"
)

func TestStdoutSinkEmit(t *testing.T) {
	t.Parallel()
	is := assert.New(t)
	must := require.New(t)

	var buf bytes.Buffer
	s := NewStdoutSink(&buf)

	must.NoError(s.Emit(context.Background(), core.Event{
		ID: "e1", Action: core.ActionLeaseIssue, Outcome: core.OutcomeSuccess,
	}))
	must.NoError(s.Emit(context.Background(), core.Event{
		ID: "e2", Action: core.ActionSessionLogin, Outcome: core.OutcomeFailure,
	}))
	must.NoError(s.Close())

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	must.Len(lines, 2, "one JSON object per line")

	var got core.Event
	must.NoError(json.Unmarshal([]byte(lines[0]), &got))
	is.Equal("e1", got.ID)
	is.Equal(core.ActionLeaseIssue, got.Action)

	must.NoError(json.Unmarshal([]byte(lines[1]), &got))
	is.Equal("e2", got.ID)
	is.Equal(core.OutcomeFailure, got.Outcome)
}
