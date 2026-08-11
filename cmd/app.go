package cmd

import (
	"errors"
	"os"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"github.com/darmiel/talmi/internal/buildinfo"
	"github.com/darmiel/talmi/internal/cli"
	"github.com/darmiel/talmi/pkg/client"
)

func buildDeps(io cli.IOStreams) Deps {
	return Deps{
		IO:    io,
		Build: buildinfo.GetBuildInfo(),
		NewClient: func() (TalmiClient, error) {
			c, err := f.GetClient()
			if err != nil {
				return nil, errServerNotConfigured()
			}
			return c, nil
		},
		RemoteAddr: func() (string, error) {
			addr, err := f.GetRemoteAddr()
			if err != nil {
				return "", errServerNotConfigured()
			}
			return addr, nil
		},
	}
}

func errServerNotConfigured() error {
	return &cli.ExitError{
		Code:    cli.CodeUsage,
		Message: "server address not configured",
		Hint:    "set --server or the TALMI_ADDR environment variable",
	}
}

func registerMigrated(root *cobra.Command, deps Deps) {
	root.AddCommand(
		newVersionCmd(deps),
		newServerCmd(deps),
		newTokenCmd(deps),
		newSessionCmd(deps),
		newAuditCmd(deps),
		newTasksCmd(deps),
	)
}

func Execute() {
	io := cli.SystemStreams()
	d := buildDeps(io)
	registerMigrated(rootCmd, d)
	rootCmd.SetOut(io.Out)
	rootCmd.SetErr(io.ErrOut)

	err := rootCmd.Execute()
	if err == nil {
		return
	}

	if _, ok := errors.AsType[*cli.ExitError](err); ok {
		os.Exit(cli.Handle(io, err))
		return
	}

	switch {
	case errors.Is(err, client.ErrInvalidSession):
		log.Error().Msg("session token is invalid or expired, please use 'talmi login' to authenticate")
		os.Exit(403)
	default:
		if bqe, ok := errors.AsType[BeQuietError](err); ok {
			if bqe.ExitCode == 0 {
				bqe.ExitCode = 1
			}
			os.Exit(bqe.ExitCode)
		}
		log.Fatal().Err(err).Msg("execution failed")
	}
}
