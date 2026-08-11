package ui

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPrinterNoColorWritesPlain(t *testing.T) {
	t.Parallel()
	var b bytes.Buffer
	p := New(&b, false)
	p.Successln("done")
	assert.Equal(t, "\u2713 done\n", b.String()) // "✓ done\n", no ANSI when color off
}

func TestPrinterErrorSymbol(t *testing.T) {
	t.Parallel()
	var b bytes.Buffer
	p := New(&b, false)
	p.Errorln("nope")
	assert.Equal(t, "\u2717 nope\n", b.String()) // "✗ nope\n"
}

func TestPrinterColorWrapsANSI(t *testing.T) {
	t.Parallel()
	var b bytes.Buffer
	p := New(&b, true)
	p.Successln("done")
	assert.Contains(t, b.String(), "done")
	assert.Contains(t, b.String(), "\x1b[", "color mode must emit ANSI")
}
