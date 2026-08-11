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
		Hint:        "run talmi session login",
		Correlation: "abc123",
	})
	assert.Equal(t, CodeAuth, code)
	assert.Empty(t, out.String(), "errors must not touch stdout")
	assert.Contains(t, errOut.String(), "session expired")
	assert.Contains(t, errOut.String(), "run talmi session login")
	assert.Contains(t, errOut.String(), "abc123")
}
