package cmd

import "github.com/jedib0t/go-pretty/v6/table"

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}

func applyTableFormat(t table.Writer) {
	s := table.StyleRounded
	s.Options = table.Options{
		SeparateHeader:  true,
		SeparateColumns: true,
	}
	//s.Format.Header = text.FormatDefault
	t.SetStyle(s)
}
