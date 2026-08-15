package cmd

import (
	"fmt"
	"strings"

	"github.com/darmiel/talmi/internal/cli/ui"
	"github.com/darmiel/talmi/internal/resolver"
	"github.com/darmiel/talmi/pkg/client"
)

type kvMulti struct {
	label  string
	values []string
}

func kvBlockMulti(p *ui.Printer, pairs []kvMulti) {
	const indent = "  "
	width := 0
	for _, kv := range pairs {
		if l := len(kv.label); l > width {
			width = l
		}
	}
	cont := strings.Repeat(" ", len(indent)+width+2)
	for _, kv := range pairs {
		label := p.Sprint(ui.StyleDim, fmt.Sprintf("%*s", width, kv.label))
		if len(kv.values) == 0 {
			p.Printf("%s%s  %s\n", indent, label, p.Sprint(ui.StyleDim, "(none)"))
			continue
		}
		p.Printf("%s%s  %s\n", indent, label, kv.values[0])
		for _, v := range kv.values[1:] {
			p.Printf("%s%s\n", cont, v)
		}
	}
}

// renderProviderList prints one aligned card per provider instance.
func renderProviderList(deps Deps, infos []client.ProviderInfo) {
	p := ui.New(deps.IO.Out, deps.IO.Color)
	for _, in := range infos {
		glyph, style := "\u2713", ui.StyleSuccess
		if in.Error != "" {
			glyph, style = "\u2717", ui.StyleError
		}
		meta := joinNonEmpty([]string{in.Realm, in.Type, in.Mode}, " \u00b7 ")
		p.Printf("%s  %s  %s\n",
			p.Sprint(style, glyph),
			p.Sprint(ui.StyleBold, in.Name),
			p.Sprint(ui.StyleDim, meta))

		if in.Error != "" {
			kvBlockMulti(p, []kvMulti{
				{label: "error", values: []string{p.Sprint(ui.StyleError, in.Error)}},
			})
		} else {
			kvBlockMulti(p, []kvMulti{
				{label: "resources", values: in.Resources},
				{label: "max actions", values: in.MaxActions},
			})
		}
		p.Println()
	}
}

func renderProviderResolve(deps Deps, results []resolver.RequestResolution, verbose bool) {
	p := ui.New(deps.IO.Out, deps.IO.Color)
	for _, rr := range results {
		acts := make([]string, len(rr.Actions))
		for i, a := range rr.Actions {
			acts[i] = string(a)
		}
		head := string(rr.Resource) + " = " + strings.Join(acts, ",")

		glyph, style := "\u2713", ui.StyleSuccess
		if rr.Chosen == "" {
			glyph, style = "\u2717", ui.StyleError
		}
		p.Printf("%s  %s\n", p.Sprint(style, glyph), p.Sprint(ui.StyleBold, head))

		pairs := make([]kvMulti, 0, 3)
		if rr.Realm != "" {
			pairs = append(pairs, kvMulti{label: "realm", values: []string{rr.Realm}})
		}
		if rr.Chosen != "" {
			pairs = append(pairs, kvMulti{label: "chosen", values: []string{rr.Chosen}})
		} else {
			pairs = append(pairs, kvMulti{label: "reason", values: []string{rr.Reason}})
		}
		if verbose && len(rr.Candidates) > 0 {
			lines := make([]string, 0, len(rr.Candidates))
			for _, c := range rr.Candidates {
				if c.Covered {
					lines = append(lines, p.Sprint(ui.StyleSuccess, "\u2713")+" "+c.Provider)
					continue
				}
				line := p.Sprint(ui.StyleError, "\u2717") + " " + c.Provider
				if c.Reason != "" {
					line += "  " + p.Sprint(ui.StyleDim, c.Reason)
				}
				lines = append(lines, line)
			}
			pairs = append(pairs, kvMulti{label: "candidates", values: lines})
		}
		kvBlockMulti(p, pairs)
		p.Println()
	}
}

func joinNonEmpty(parts []string, sep string) string {
	out := make([]string, 0, len(parts))
	for _, s := range parts {
		if s != "" {
			out = append(out, s)
		}
	}
	return strings.Join(out, sep)
}
