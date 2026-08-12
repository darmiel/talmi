package cli

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHandleNilIsOK(t *testing.T) {
	t.Parallel()
	io, _, _ := TestStreams()
	assert.Equal(t, CodeOK, Handle(io, nil))
}

func TestHandlePlainErrorIsGeneric(t *testing.T) {
	t.Parallel()
	io, _, errOut := TestStreams()
	code := Handle(io, errors.New("boom"))
	assert.Equal(t, CodeGeneric, code)
	assert.Contains(t, errOut.String(), "boom")
}

func TestHandleExitErrorRendersCodeHintCorrelation(t *testing.T) {
	t.Parallel()
	io, out, errOut := TestStreams()
	code := Handle(io, &ExitError{
		Code:        CodeAuth,
		Message:     "session expired",
		Hints:       []string{"run talmi session login"},
		Correlation: "abc123",
	})
	assert.Equal(t, CodeAuth, code)
	assert.Empty(t, out.String(), "errors must not touch stdout")
	assert.Contains(t, errOut.String(), "session expired")
	assert.Contains(t, errOut.String(), "run talmi session login")
	assert.Contains(t, errOut.String(), "abc123")
}

func TestHandleRendersDetailMultiHintAndCause(t *testing.T) {
	t.Parallel()
	io, out, errOut := TestStreams()
	code := Handle(io, &ExitError{
		Code:    CodeGeneric,
		Message: "can't reach the Talmi server",
		Detail:  "the connection was refused",
		Hints:   []string{"is the server running?", "or use --server"},
		Cause:   errors.New("dial tcp 127.0.0.1:8080: connect: connection refused"),
	})
	assert.Equal(t, CodeGeneric, code)
	assert.Empty(t, out.String())

	s := errOut.String()
	assert.Contains(t, s, "can't reach the Talmi server")
	assert.Contains(t, s, "the connection was refused")
	assert.Contains(t, s, "is the server running?")
	assert.Contains(t, s, "or use --server")
	assert.Contains(t, s, "connection refused", "the raw cause must be shown")
}
