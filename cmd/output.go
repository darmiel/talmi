package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

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
			_ = ee.Trace(correlation)
		}
		return ee
	}

	// expired / invalid session
	if errors.Is(err, client.ErrInvalidSession) {
		msg := "session is invalid or expired"
		if exp := savedSessionExpiry(); !exp.IsZero() && time.Now().After(exp) {
			msg = fmt.Sprintf("your session expired %s ago", time.Since(exp).Round(time.Second))
		}
		return cli.Fail(cli.CodeAuth, msg).
			Hint("run `talmi session login` to authenticate").
			Trace(correlation).
			Because(err)
	}

	// timeout / cancellation
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return cli.Fail(cli.CodeGeneric, "operation timed out").
			Hint("the server may be slow or unreachable; try again later").
			Trace(correlation).
			Because(err)
	case errors.Is(err, context.Canceled):
		return cli.Fail(cli.CodeGeneric, "operation canceled").Trace(correlation).Because(err)
	}

	// structured API error from client
	if apiErr, ok := errors.AsType[client.APIError](err); ok {
		return classifyAPIError(apiErr, correlation)
	}

	if isUsageError(err) {
		return cli.Fail(cli.CodeUsage, err.Error())
	}
	return cli.Fail(cli.CodeGeneric, err.Error())
}

func classifyAPIError(apiErr client.APIError, correlation string) *cli.ExitError {
	trace := apiErr.CorrelationID
	if trace == "" {
		trace = correlation
	}
	ee := cli.Fail(cli.CodeGeneric, apiErr.Message).Trace(trace)
	switch {
	case apiErr.StatusCode == 401:
		ee.Code = cli.CodeAuth
		_ = ee.Hint("run `talmi session login` to authenticate")
	case apiErr.StatusCode == 403:
		ee.Code = cli.CodeDenied
		_ = ee.Hint(
			"you're authenticated but not authorized to perform this",
			"check that your roles grant it",
		)
	case apiErr.StatusCode == 404:
		ee.Code = cli.CodeDenied
	case apiErr.StatusCode >= 500:
		_ = ee.Hint("the server may be starting up or overloaded; try again later")
	}
	return ee
}

func serverHostFromErr(err error) string {
	if urlErr, ok := errors.AsType[*url.Error](err); ok {
		if u, e := url.Parse(urlErr.URL); e == nil {
			return u.Host
		}
	}
	return ""
}

func isUsageError(err error) bool {
	msg := err.Error()
	for _, p := range []string{
		"unknown command", "unknown flag", "unknown shorthand flag",
		"required flag", "invalid argument", "accepts", "requires",
	} {
		if strings.Contains(msg, p) {
			return true
		}
	}
	return false
}

func clientError(err error, correlation string) error {
	if err == nil {
		return nil
	}
	if netErr, ok := errors.AsType[net.Error](err); ok {
		target := "the Talmi server"
		if host := serverHostFromErr(err); host != "" {
			target = "the Talmi server at " + host
		}
		detail := "the connection was refused or the host is unreachable"
		if netErr.Timeout() {
			detail = "the connection timed out"
		}
		return cli.Fail(cli.CodeGeneric, "can't reach "+target).
			Detailed(detail).
			Hint(
				"is the server running? start it with `talmi server run`",
				"or target another server with `--server` (or `$TALMI_ADDR`)",
			).
			Because(err)
	}
	return classify(err, correlation)
}
