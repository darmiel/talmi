package cmd

import (
	"encoding/json"
	"errors"

	"github.com/spf13/cobra"

	"github.com/darmiel/talmi/internal/cli"
	"github.com/darmiel/talmi/pkg/client"
)

// addJSON registers a --json flag and returns a pointer to its value.
func addJSONFlag(cmd *cobra.Command) *bool {
	return cmd.Flags().Bool("json", false, "output as JSON")
}

// emitJSON writes v to the data stream as indented JSON.
func emitJSON(d Deps, v any) error {
	enc := json.NewEncoder(d.IO.Out)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// clientError maps a [client]-error to a [cli.ExitError] and returns it.
func clientError(err error, correlation string) error {
	if errors.Is(err, client.ErrInvalidSession) {
		return &cli.ExitError{
			Code:        cli.CodeAuth,
			Message:     "session is invalid or expired",
			Hint:        "run 'talmi session login' to authenticate",
			Correlation: correlation,
			Cause:       err,
		}
	}
	msg := err.Error()
	if apiErr, ok := errors.AsType[client.APIError](err); ok {
		msg = apiErr.Message
		if correlation == "" {
			correlation = apiErr.CorrelationID
		}
	}
	return &cli.ExitError{
		Code:        cli.CodeGeneric,
		Message:     msg,
		Correlation: correlation,
		Cause:       err,
	}
}
