package ui

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSpinnerDisabledIsSilent(t *testing.T) {
	t.Parallel()
	var b bytes.Buffer
	s := NewSpinner(&b, false)
	s.Start("working")
	s.Stop("done")
	assert.Empty(t, b.String())
}

func TestSpinnerEnabledWritesFinalMessage(t *testing.T) {
	t.Parallel()
	var b bytes.Buffer
	s := NewSpinner(&b, true)
	s.Start("working")
	s.Stop("done")
	assert.Contains(t, b.String(), "done")
}

func TestSpinnerStopIdempotent(t *testing.T) {
	t.Parallel()
	var b bytes.Buffer
	s := NewSpinner(&b, true)
	s.Start("x")
	s.Stop("a")
	s.Stop("b") // second Stop must not panic or block
}

func TestSpinnerStopClearsLine(t *testing.T) {
	t.Parallel()
	var b bytes.Buffer
	s := NewSpinner(&b, true)
	s.Start("a very long working message")
	s.Stop("ok")

	out := b.String()
	// erase-to-end-of-line so a shorter final can't leave leftover characters
	assert.Contains(t, out, "\r\x1b[K")
	assert.Contains(t, out, "ok")
	assert.True(t, strings.HasSuffix(out, "ok\n"))
}

func TestSpinnerStopEmptyClearsWithoutNewline(t *testing.T) {
	t.Parallel()
	var b bytes.Buffer
	s := NewSpinner(&b, true)
	s.Start("working")
	s.Stop("")

	out := b.String()
	assert.True(t, strings.HasSuffix(out, "\r\x1b[K"), "empty final clears the line")
	assert.NotContains(t, out, "\n", "empty final must not add a blank line")
}
