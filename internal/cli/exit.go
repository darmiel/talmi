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
	Message     string
	Hint        string
	Correlation string
	Cause       error
}

func (e *ExitError) Error() string {
	return e.Message
}

func (e *ExitError) Unwrap() error {
	return e.Cause
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
	if exitErr.Hint != "" {
		p.Hintln("%s", exitErr.Hint)
	}
	if exitErr.Correlation != "" {
		p.Faintln("correlation: %s", exitErr.Correlation)
	}
	return exitErr.Code
}
