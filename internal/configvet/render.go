package configvet

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/fatih/color"
)

// RenderJSON writes the full report as JSON.
func RenderJSON(w io.Writer, r Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(struct {
		Findings []Finding `json:"findings"`
		Errors   int       `json:"errors"`
		Warnings int       `json:"warnings"`
	}{
		Findings: r.Findings,
		Errors:   len(r.Errors()),
		Warnings: len(r.Warnings()),
	})
}

// RenderText writes a human-friendly report.
func RenderText(w io.Writer, r Report, useColor bool) {
	green := colorizer(useColor, color.FgGreen)

	if len(r.Findings) == 0 {
		_, _ = fmt.Fprintln(w, green("configuration is valid"))
		return
	}

	red := colorizer(useColor, color.FgRed)
	yellow := colorizer(useColor, color.FgYellow)
	dim := colorizer(useColor, color.Faint)
	bold := colorizer(useColor, color.Bold)

	findings := append([]Finding(nil), r.Findings...)
	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].Severity != findings[j].Severity {
			return findings[i].Severity < findings[j].Severity // Error(0) before Warn(1)
		}
		if findings[i].Section != findings[j].Section {
			return findings[i].Section < findings[j].Section
		}
		return findings[i].Location < findings[j].Location
	})

	for _, f := range findings {
		label := yellow("warn")
		if f.Severity == SeverityError {
			label = red("error")
		}
		_, _ = fmt.Fprintf(w, "%s%s %s\n", label, dim("["+f.Code+"]"), bold(f.Location))

		switch {
		case f.Pos.Line > 0:
			_, _ = fmt.Fprintf(w, "  %s %s:%d:%d\n", dim("-->"), f.Pos.File, f.Pos.Line, f.Pos.Column)
		case f.Pos.File != "":
			_, _ = fmt.Fprintf(w, "  %s %s\n", dim("-->"), f.Pos.File)
		}

		_, _ = fmt.Fprintf(w, "  %s\n", f.Message)
		if f.Detail != "" {
			_, _ = fmt.Fprintf(w, "  %s\n", f.Detail)
		}
		if len(f.Suggestions) > 0 {
			_, _ = fmt.Fprintf(w, "  %s %s\n", dim("did you mean:"), strings.Join(f.Suggestions, ", "))
		}
		if f.Help != "" {
			_, _ = fmt.Fprintf(w, "  %s %s\n", dim("help:"), f.Help)
		}
		_, _ = fmt.Fprintln(w)
	}

	ne, nw := len(r.Errors()), len(r.Warnings())
	summary := fmt.Sprintf("%d error(s), %d warning(s)", ne, nw)
	switch {
	case ne > 0:
		summary = red(summary)
	case nw > 0:
		summary = yellow(summary)
	}
	_, _ = fmt.Fprintln(w, summary)
}

func colorizer(useColor bool, attrs ...color.Attribute) func(string) string {
	if !useColor {
		return func(s string) string { return s }
	}
	sprint := color.New(attrs...).SprintFunc()
	return func(s string) string { return sprint(s) }
}
