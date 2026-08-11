package cli

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTestStreamsCaptureSeparately(t *testing.T) {
	t.Parallel()
	io, out, errOut := TestStreams()
	_, _ = io.Out.Write([]byte("result"))
	_, _ = io.ErrOut.Write([]byte("diag"))
	assert.Equal(t, "result", out.String())
	assert.Equal(t, "diag", errOut.String())
	assert.False(t, io.IsTTY, "test streams must not be a TTY")
	assert.False(t, io.Color, "test streams must not enable color")
}
