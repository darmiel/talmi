package ui

import (
	"fmt"
	"io"

	"github.com/fatih/color"
	"github.com/jedib0t/go-pretty/v6/table"
)

// NewTable returns a table.Writer that renders a rounded, separated style to w.
func NewTable(w io.Writer) table.Writer {
	tw := table.NewWriter()
	tw.SetOutputMirror(w)

	s := table.StyleRounded
	s.Options = table.Options{
		SeparateHeader:  true,
		SeparateColumns: true,
	}
	tw.SetStyle(s)

	return tw
}

// WriteKV writes right-aligned "key: value" pairs to w, one per line.
// Keys are faint when color is enabled.
func WriteKV(w io.Writer, useColor bool, pairs [][2]string) {
	width := 0
	for _, kv := range pairs {
		if len(kv[0]) > width {
			width = len(kv[0])
		}
	}
	pr := New(w, useColor)
	for _, kv := range pairs {
		key := fmt.Sprintf("%*s", width, kv[0]) // right-align to the widest key
		pr.Printf("%s: %s\n", pr.colorize(key, color.Faint), kv[1])
	}
}
