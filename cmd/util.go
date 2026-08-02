package cmd

import "github.com/jedib0t/go-pretty/v6/table"

func applyTableFormat(t table.Writer) {
	s := table.StyleRounded
	s.Options = table.Options{
		SeparateHeader:  true,
		SeparateColumns: true,
	}
	// s.Format.Header = text.FormatDefault
	t.SetStyle(s)
}
