package ui

import (
	"fmt"
	"io"
	"regexp"

	"github.com/fatih/color"
)

const (
	symSuccess = "\u2713" // ✓
	symError   = "\u2717" // ✗
	symWarn    = "!"
	symHint    = "\u2192" // →
)

var codeSpan = regexp.MustCompile("`([^`]+)`")

// Printer renders stylized text to the terminal.
type Printer struct {
	w     io.Writer
	color bool
}

func New(w io.Writer, color bool) *Printer {
	return &Printer{
		w:     w,
		color: color,
	}
}

func (p *Printer) colorize(s string, attrs ...color.Attribute) string {
	c := color.New(attrs...)
	if p.color {
		c.EnableColor()
	} else {
		c.DisableColor()
	}
	return c.Sprint(s)
}

// emphasize renders `backtick` spans as bold-cyan and drops the backticks, so
// commands and flags in messages stand out and read as copy-pasteable.
func (p *Printer) emphasize(s string) string {
	return codeSpan.ReplaceAllStringFunc(s, func(m string) string {
		return p.colorize(m[1:len(m)-1], color.FgCyan, color.Bold)
	})
}

func (p *Printer) symbolLine(sym string, attr color.Attribute, msg string, args ...any) {
	_, _ = fmt.Fprintf(p.w, "%s %s\n", p.colorize(sym, attr), fmt.Sprintf(msg, args...))
}

func (p *Printer) Successln(msg string, args ...any) {
	p.symbolLine(symSuccess, color.FgGreen, msg, args...)
}

// Errorln renders a bold error headline: a red ✗ followed by the bold message.
func (p *Printer) Errorln(msg string, args ...any) {
	_, _ = fmt.Fprintf(p.w, "%s %s\n",
		p.colorize(symError, color.FgRed, color.Bold),
		p.colorize(fmt.Sprintf(msg, args...), color.Bold),
	)
}

func (p *Printer) Warnln(msg string, args ...any) {
	p.symbolLine(symWarn, color.FgYellow, msg, args...)
}

// Hintln renders an indented, dim → followed by the message, with `backtick`
// spans emphasized.
func (p *Printer) Hintln(msg string, args ...any) {
	_, _ = fmt.Fprintf(p.w, "  %s %s\n",
		p.colorize(symHint, color.Faint),
		p.emphasize(fmt.Sprintf(msg, args...)),
	)
}

func (p *Printer) Faintln(msg string, args ...any) {
	_, _ = fmt.Fprintln(p.w, p.colorize(fmt.Sprintf(msg, args...), color.Faint))
}

func (p *Printer) Boldln(msg string, args ...any) {
	_, _ = fmt.Fprintln(p.w, p.colorize(fmt.Sprintf(msg, args...), color.Bold))
}

func (p *Printer) Headingln(msg string, args ...any) {
	_, _ = fmt.Fprintln(p.w, p.colorize(fmt.Sprintf(msg, args...), color.Bold, color.Underline))
}

func (p *Printer) Printf(msg string, args ...any) {
	_, _ = fmt.Fprintf(p.w, msg, args...)
}

func (p *Printer) Println(args ...any) {
	_, _ = fmt.Fprintln(p.w, args...)
}

func (p *Printer) Writer() io.Writer {
	return p.w
}
