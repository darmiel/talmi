package cmd

import (
	"os"

	"github.com/spf13/cobra"

	"github.com/darmiel/talmi/internal/buildinfo"
	"github.com/darmiel/talmi/internal/cli"
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
		newLeaseCmd(deps),
		newConfigCmd(deps),
	)
}

func Execute() {
	io := cli.SystemStreams()
	d := buildDeps(io)
	registerMigrated(rootCmd, d)
	rootCmd.SetOut(io.Out)
	rootCmd.SetErr(io.ErrOut)

	os.Exit(cli.Handle(io, rootCmd.Execute()))
}
