package cli

import (
	"errors"

	"github.com/darmiel/talmi/internal/cli/ui"
)

// Process exit codes
const (
	CodeOK      = 0
	CodeGeneric = 1
	CodeUsage   = 2
	CodeConfig  = 3
	CodeAuth    = 4
	CodeDenied  = 5
)

// ExitError is the single error type the root handler understands.
type ExitError struct {
	Code        int
	Message     string   // headline
	Detail      string   // optional one-line "why"
	Hints       []string // actionable next steps
	Correlation string   // correlation ID for server-sent errors
	Cause       error    // raw underlying error
}

func (e *ExitError) Error() string {
	return e.Message
}

func (e *ExitError) Unwrap() error {
	return e.Cause
}

func Fail(code int, message string) *ExitError {
	return &ExitError{
		Code:    code,
		Message: message,
	}
}

func (e *ExitError) Detailed(d string) *ExitError {
	e.Detail = d
	return e
}

func (e *ExitError) Hint(h ...string) *ExitError {
	e.Hints = append(e.Hints, h...)
	return e
}

func (e *ExitError) Because(err error) *ExitError {
	e.Cause = err
	return e
}

func (e *ExitError) Trace(correlation string) *ExitError {
	e.Correlation = correlation
	return e
}

func Handle(io IOStreams, err error) int {
	if err == nil {
		return CodeOK
	}
	var exitErr *ExitError
	if !errors.As(err, &exitErr) {
		exitErr = &ExitError{
			Code:    CodeGeneric,
			Message: err.Error(),
		}
	}
	if exitErr.Code == CodeOK {
		exitErr.Code = CodeGeneric
	}

	p := ui.New(io.ErrOut, io.Color)
	p.Errorln("%s", exitErr.Message)
	if exitErr.Detail != "" {
		p.Faintln("  %s", exitErr.Detail)
	}
	if len(exitErr.Hints) > 0 {
		p.Println()
		for _, hint := range exitErr.Hints {
			p.Hintln("%s", hint)
		}
	}

	if exitErr.Cause != nil || exitErr.Correlation != "" {
		p.Println()
	}
	if exitErr.Cause != nil {
		p.Faintln("  %s", exitErr.Cause.Error())
	}
	if exitErr.Correlation != "" {
		p.Faintln("  correlation: %s", exitErr.Correlation)
	}
	return exitErr.Code
}
