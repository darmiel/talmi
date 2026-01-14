package cmd

import (
	"fmt"

	"github.com/fatih/color"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"github.com/darmiel/talmi/internal/buildinfo"
)

var infoCmd = &cobra.Command{
	Use:   "info",
	Short: "Show information about the Talmi installation",
	RunE: func(cmd *cobra.Command, args []string) error {
		if f.RemoteAddr == "" {
			return infoLocally(cmd, args)
		}
		return infoRemote(cmd, args)
	},
}

func init() {
	rootCmd.AddCommand(infoCmd)
}

func infoRemote(cmd *cobra.Command, _ []string) error {
	cli, err := f.GetClient()
	if err != nil {
		return err
	}
	log.Info().Msg("Fetching build info from server...")
	info, err := cli.Info(cmd.Context())
	if err != nil {
		return fmt.Errorf("failed to get info from server: %w", err)
	}
	printInfo(info)
	return nil
}

func infoLocally(_ *cobra.Command, _ []string) error {
	log.Info().Msg("Showing local build info...")
	info := buildinfo.GetBuildInfo()
	printInfo(&info)
	return nil
}

func printInfo(info *buildinfo.Info) {
	bold := color.New(color.Bold).SprintFunc()
	faint := color.New(color.Faint).SprintFunc()

	fmt.Println(bold("\n── Talmi Build Information ──"))
	fmt.Printf("  %s:    %s\n", faint("Version"), info.Version)
	fmt.Printf("  %s:     %s\n", faint("Commit"), info.CommitHash)
}
