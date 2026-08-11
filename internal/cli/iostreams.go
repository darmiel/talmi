package cli

import (
	"bytes"
	"io"
	"os"

	"github.com/mattn/go-isatty"
)

// IOStreams provides a way to abstract the input and output streams of a command line application.
// It also contains information like whether the output is a terminal and whether color is allowed on the primary stream.
type IOStreams struct {
	In     io.Reader
	Out    io.Writer
	ErrOut io.Writer

	IsTTY bool // stdout is a terminal (spinners, ...)
	Color bool // color allowed on the primary stream?
}

// SystemStreams wires os.Stdin, os.Stdout and os.Stderr into an IOStreams and detects whether
// the output is a terminal and whether color is allowed on the primary stream.
func SystemStreams() IOStreams {
	fd := os.Stdout.Fd()
	tty := isatty.IsTerminal(fd) || isatty.IsCygwinTerminal(fd)
	return IOStreams{
		In:     os.Stdin,
		Out:    os.Stdout,
		ErrOut: os.Stderr,

		IsTTY: tty,
		Color: tty && os.Getenv("NO_COLOR") == "",
	}
}

// TestStreams returns a non-tty IOStreams and buffers to capture output.
func TestStreams() (IOStreams, *bytes.Buffer, *bytes.Buffer) {
	out, errOut := &bytes.Buffer{}, &bytes.Buffer{}
	i := IOStreams{
		In:     &bytes.Buffer{},
		Out:    out,
		ErrOut: errOut,
		IsTTY:  false,
		Color:  false,
	}
	return i, out, errOut
}
