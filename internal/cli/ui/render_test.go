package ui

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewTableRendersRoundedWithHeader(t *testing.T) {
	t.Parallel()
	var b bytes.Buffer
	tw := NewTable(&b)
	tw.AppendHeader([]any{"Name", "Status"})
	tw.AppendRow([]any{"gh-ci", "ready"})
	tw.Render()

	out := b.String()
	assert.Contains(t, strings.ToUpper(out), "NAME") // go-pretty uppercases headers by default
	assert.Contains(t, out, "gh-ci")
	assert.True(t, strings.ContainsAny(out, "\u256d\u2570\u2500"), "expected rounded border runes")
}

func TestWriteKVAlignsPairs(t *testing.T) {
	t.Parallel()
	var b bytes.Buffer
	WriteKV(&b, false, [][2]string{
		{"Version", "1.2.3"},
		{"Commit", "abc123"},
	})

	out := b.String()
	assert.Contains(t, out, "Version")
	assert.Contains(t, out, "1.2.3")
	assert.Contains(t, out, "Commit")
	assert.Contains(t, out, "abc123")
	// keys are right-aligned to the widest key ("Version" = 7), so "Commit" (6) gets one pad
	assert.Contains(t, out, " Commit: abc123")
}
