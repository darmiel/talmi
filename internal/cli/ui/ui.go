package ui

import (
	"fmt"
	"io"

	"github.com/fatih/color"
)

const (
	symSuccess = "\u2713" // ✓
	symError   = "\u2717" // ✗
	symWarn    = "!"
	symHint    = "->"
)

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

func (p *Printer) symbolLine(sym string, attr color.Attribute, msg string, args ...any) {
	_, _ = fmt.Fprintf(p.w, "%s %s\n", p.colorize(sym, attr), fmt.Sprintf(msg, args...))
}

func (p *Printer) Successln(msg string, args ...any) {
	p.symbolLine(symSuccess, color.FgGreen, msg, args...)
}

func (p *Printer) Errorln(msg string, args ...any) {
	p.symbolLine(symError, color.FgRed, msg, args...)
}

func (p *Printer) Warnln(msg string, args ...any) {
	p.symbolLine(symWarn, color.FgYellow, msg, args...)
}

func (p *Printer) Hintln(msg string, args ...any) {
	p.symbolLine(symHint, color.FgCyan, msg, args...)
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
