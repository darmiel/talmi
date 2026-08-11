package ui

import (
	"bytes"
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
