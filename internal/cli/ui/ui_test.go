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

func TestHintlnStripsBackticksAndKeepsText(t *testing.T) {
	t.Parallel()
	var b bytes.Buffer
	p := New(&b, false)
	p.Hintln("run `talmi server run` now")
	out := b.String()
	assert.Contains(t, out, "talmi server run", "emphasized text must survive")
	assert.NotContains(t, out, "`", "backticks must be stripped")
	assert.Contains(t, out, "\u2192", "hint uses the → arrow")
}

func TestHintlnEmphasisIsColoredInColorMode(t *testing.T) {
	t.Parallel()
	var b bytes.Buffer
	p := New(&b, true)
	p.Hintln("try `x`")
	assert.Contains(t, b.String(), "\x1b[", "emphasis must emit ANSI")
	assert.NotContains(t, b.String(), "`")
}
