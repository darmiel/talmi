package cmd

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/darmiel/talmi/internal/cli/ui"
	"github.com/darmiel/talmi/internal/core"
	"github.com/darmiel/talmi/pkg/client"
)

func outcomeStyle(o core.Outcome) (string, ui.Style) {
	switch o {
	case core.OutcomeSuccess:
		return "\u2713", ui.StyleSuccess // ✓
	case core.OutcomeDenied:
		return "\u26a0", ui.StyleWarn // ⚠
	default:
		return "\u2717", ui.StyleError // ✗
	}
}

func outcomeWord(o core.Outcome) string {
	if o == core.OutcomeFailure {
		return "failed"
	}
	return string(o)
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

func shortRev(rev string) string {
	if len(rev) > 7 {
		return rev[:7]
	}
	return rev
}

// requestedResources returns "resource  action1, action2" lines for each
// resource in the event's decision.
func requestedResources(e core.Event) []string {
	if e.Decision == nil || len(e.Decision.PerRequest) == 0 {
		return nil
	}
	out := make([]string, 0, len(e.Decision.PerRequest))
	for _, rd := range e.Decision.PerRequest {
		line := string(rd.Request.Resource)
		if len(rd.Request.Actions) > 0 {
			acts := make([]string, len(rd.Request.Actions))
			for i, a := range rd.Request.Actions {
				acts[i] = string(a)
			}
			line += "  " + strings.Join(acts, ", ")
		}
		out = append(out, line)
	}
	return out
}

func renderRequestedResources(p *ui.Printer, indent string, resources []string) {
	if len(resources) == 0 {
		return
	}
	const label = "resources"
	p.Printf("%s%s  %s\n", indent, p.Sprint(ui.StyleDim, label), resources[0])
	cont := strings.Repeat(" ", len(indent)+len(label)+2)
	for _, r := range resources[1:] {
		p.Printf("%s%s\n", cont, r)
	}
}

// kvBlock prints "  label  value" lines with right-aligned dim labels so the
// values form a clean left edge. Empty values are skipped. Values may already
// carry styling (ANSI); only the label is styled here.
func kvBlock(p *ui.Printer, indent string, pairs [][2]string) {
	width := 0
	for _, kv := range pairs {
		if kv[1] == "" {
			continue
		}
		if l := len(kv[0]); l > width {
			width = l
		}
	}
	for _, kv := range pairs {
		if kv[1] == "" {
			continue
		}
		p.Printf("%s%s  %s\n", indent, p.Sprint(ui.StyleDim, fmt.Sprintf("%*s", width, kv[0])), kv[1])
	}
}

// renderAuditSummary prints a dim one-line summary of the result set.
func renderAuditSummary(p *ui.Printer, entries []core.Event, filters string) {
	var ok, denied, failed int
	for _, e := range entries {
		switch e.Outcome {
		case core.OutcomeSuccess:
			ok++
		case core.OutcomeDenied:
			denied++
		default:
			failed++
		}
	}
	noun := "entries"
	if len(entries) == 1 {
		noun = "entry"
	}
	line := fmt.Sprintf("%d %s · %d ok · %d denied · %d failed", len(entries), noun, ok, denied, failed)
	if filters != "" {
		line += " · " + filters
	}
	p.Faintln("%s", line)
	p.Println()
}

// renderAuditCard prints one entry: a tight two-line block for routine
// successes, an expanded aligned card for denials and failures.
func renderAuditCard(p *ui.Printer, now time.Time, e core.Event) {
	glyph, style := outcomeStyle(e.Outcome)
	rel := ui.RelativeTime(now, e.Time)

	if e.Outcome == core.OutcomeSuccess {
		p.Printf("%s  %s  %s\n",
			p.Sprint(style, glyph),
			p.Sprint(ui.StyleBold, string(e.Action)),
			p.Sprint(ui.StyleDim, rel))

		who := "-"
		if e.Actor != nil {
			who = e.Actor.ID
		}
		ctx := who
		if n := len(e.Artifacts); n > 0 {
			ctx += p.Sprint(ui.StyleDim, fmt.Sprintf(" · %d artifact%s", n, plural(n)))
		}
		if e.NodeID != "" {
			ctx += p.Sprint(ui.StyleDim, " · "+e.NodeID)
		}
		ctx += p.Sprint(ui.StyleDim, " · "+e.ID)
		p.Printf("   %s\n", ctx)
		renderRequestedResources(p, "   ", requestedResources(e))
		p.Println()
		return
	}

	// denied / failure: headline + aligned detail block
	p.Printf("%s  %s  %s %s\n",
		p.Sprint(style, glyph),
		p.Sprint(ui.StyleBold, string(e.Action)),
		p.Sprint(style, outcomeWord(e.Outcome)),
		p.Sprint(ui.StyleDim, "· "+rel))

	pairs := make([][2]string, 0, 6)
	if e.Actor != nil {
		who := e.Actor.ID
		if e.Actor.Issuer != "" {
			who += " (" + e.Actor.Issuer + ")"
		}
		pairs = append(pairs, [2]string{"principal", who})
	}
	pairs = append(pairs,
		[2]string{"request", e.RequestID},
		[2]string{"session", e.SessionID},
		[2]string{"node", e.NodeID},
		[2]string{"revision", shortRev(e.Revision)},
	)
	if e.Error != "" {
		pairs = append(pairs, [2]string{"error", p.Sprint(ui.StyleError, e.Error)})
	}
	pairs = append(pairs, [2]string{"id", p.Sprint(ui.StyleDim, e.ID)})
	kvBlock(p, "   ", pairs)
	renderRequestedResources(p, "   ", requestedResources(e))
	p.Println()
}

// renderAuditDetail prints the sectioned single-entry view. It builds its own
// Printer from deps so it can reuse renderDecision.
func renderAuditDetail(deps Deps, e core.Event) {
	p := ui.New(deps.IO.Out, deps.IO.Color)
	glyph, style := outcomeStyle(e.Outcome)

	p.Printf("%s  %s · %s\n",
		p.Sprint(style, glyph),
		p.Sprint(ui.StyleBold, string(e.Action)),
		p.Sprint(style, string(e.Outcome)))

	p.Println()
	p.Headingln("Trace")
	kvBlock(p, "  ", [][2]string{
		{"time", e.Time.Local().Format("2006-01-02 15:04:05 MST") + " (" + e.Time.UTC().Format("15:04:05") + " UTC)"},
		{"request", e.RequestID},
		{"session", e.SessionID},
		{"node", e.NodeID},
		{"revision", e.Revision},
		{"id", e.ID},
	})

	if e.Actor != nil {
		p.Println()
		p.Headingln("Actor")
		kvBlock(p, "  ", [][2]string{
			{"principal", e.Actor.ID},
			{"issuer", e.Actor.Issuer},
			{"teams", teamsOf(e.Actor)},
		})
	}

	if len(e.Metadata) > 0 {
		p.Println()
		p.Headingln("Metadata")
		keys := make([]string, 0, len(e.Metadata))
		for k := range e.Metadata {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		pairs := make([][2]string, 0, len(keys))
		for _, k := range keys {
			pairs = append(pairs, [2]string{k, fmt.Sprintf("%v", e.Metadata[k])})
		}
		kvBlock(p, "  ", pairs)
	}

	if len(e.Artifacts) > 0 {
		p.Println()
		p.Headingln("Artifacts")
		for _, a := range e.Artifacts {
			line := a.Provider
			if a.Fingerprint != "" {
				line += "  fp " + a.Fingerprint
			}
			line += "  " + a.ArtifactID
			p.Printf("  %s %s\n", p.Sprint(ui.StyleDim, "•"), p.Sprint(ui.StyleDim, line))
		}
	}

	if e.Decision != nil {
		p.Println()
		p.Headingln("Decision")
		renderDecision(deps, *e.Decision)
	}

	if e.Error != "" {
		p.Println()
		p.Headingln("Error")
		p.Printf("  %s\n", p.Sprint(ui.StyleError, e.Error))
	}
}

func teamsOf(a *core.Principal) string {
	raw, ok := a.Attributes["teams"]
	if !ok {
		return ""
	}
	switch v := raw.(type) {
	case []any:
		parts := make([]string, 0, len(v))
		for _, t := range v {
			parts = append(parts, fmt.Sprintf("%v", t))
		}
		return strings.Join(parts, ", ")
	case []string:
		return strings.Join(v, ", ")
	default:
		return fmt.Sprintf("%v", raw)
	}
}

// auditFilterSummary renders the active filters for the summary header.
func auditFilterSummary(f client.AuditFilter) string {
	var parts []string
	add := func(k, v string) {
		if v != "" {
			parts = append(parts, k+"="+v)
		}
	}
	add("action", f.Action)
	add("outcome", f.Outcome)
	add("principal", f.ActorID)
	add("request", f.RequestID)
	add("session", f.SessionID)
	add("node", f.NodeID)
	add("fingerprint", f.Fingerprint)
	add("since", f.Since)
	add("until", f.Until)
	return strings.Join(parts, " ")
}
