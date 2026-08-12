package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"net"

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

// classify turns any error into a [cli.ExitError] with an appropriate exit code and message.
func classify(err error, correlation string) error {
	if err == nil {
		return nil
	}

	// already classified by a command?
	if ee, ok := errors.AsType[*cli.ExitError](err); ok {
		if ee.Correlation == "" {
			return ee.Trace(correlation)
		}
		return ee
	}

	// expired / invalid session
	if errors.Is(err, client.ErrInvalidSession) {
		return cli.Fail(cli.CodeAuth, "session is invalid or expired").
			Hint("run 'talmi session login' to authenticate").
			Trace(correlation).
			Because(err)
	}

	// timeout / cancellation
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return cli.Fail(cli.CodeGeneric, "operation timed out").Trace(correlation).Because(err)
	case errors.Is(err, context.Canceled):
		return cli.Fail(cli.CodeGeneric, "operation canceled").Trace(correlation).Because(err)
	}

	// network failures
	if netErr, ok := errors.AsType[net.Error](err); ok {
		detail := "the connection was refused or the host is unreachable"
		if netErr.Timeout() {
			detail = "the connection timed out"
		}
		return cli.Fail(cli.CodeGeneric, "can't reach the Talmi server").
			Detailed(detail).
			Hint(
				"is the server running? start it with 'talmi server run'",
				"or target another server with --server (or $TALMI_ADDR)",
			).
			Because(err)
	}

	// structured API error from client
	if apiErr, ok := errors.AsType[client.APIError](err); ok {
		trace := apiErr.CorrelationID
		if trace == "" {
			trace = correlation
		}
		ee := cli.Fail(cli.CodeGeneric, apiErr.Message).Trace(trace)
		switch apiErr.StatusCode {
		case 401, 403:
			ee.Code = cli.CodeAuth
			_ = ee.Hint("you may need to authenticate: talmi session login")
		case 404:
			ee.Code = cli.CodeDenied
		}
		return ee
	}

	return cli.Fail(cli.CodeGeneric, err.Error())
}

func clientError(err error, correlation string) error {
	return classify(err, correlation)
}
