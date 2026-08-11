package cmd

import (
	"github.com/spf13/cobra"

	"github.com/darmiel/talmi/internal/cli/ui"
)

func newVersionCmd(deps Deps) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "version",
		Short: "Show version and build information",
		Args:  cobra.NoArgs,
	}
	jsonOut := addJSONFlag(cmd)
	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		info := deps.Build

		// prefer the remote information if provided
		if remote, err := deps.RemoteAddr(); err == nil && remote != "" {
			if c, err := deps.NewClient(); err == nil {
				if remote, _, err := c.Info(cmd.Context()); err == nil {
					info = *remote
				}
			}
		}
		if *jsonOut {
			return emitJSON(deps, info)
		}
		ui.WriteKV(deps.IO.Out, deps.IO.Color, [][2]string{
			{"Version", info.Version},
			{"Commit", info.CommitHash},
		})
		return nil
	}
	return cmd
}
