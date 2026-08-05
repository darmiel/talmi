package cmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/darmiel/talmi/internal/config"
	"github.com/darmiel/talmi/internal/configvet"
	"github.com/darmiel/talmi/internal/source"
)

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Interact with the configuration",
	Long:  `Utilities for validating and viewing the Talmi configuration`,
}

var (
	vetStrict bool
	vetFormat string
)

var configVetCmd = &cobra.Command{
	Use:   "vet [config.yaml]",
	Short: "Validate a Talmi configuration",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		path := "talmi.yaml"
		if len(args) == 1 {
			path = args[0]
		}

		cfg, err := config.Load(path)
		if err != nil {
			return logError(err, "", "could not load config")
		}
		sourced, _, err := source.NewLocalSource(filepath.Dir(path), cfg).Load(context.Background())
		if err != nil {
			return logError(err, "", "could not load sourced config tree")
		}

		report := configvet.Static(configvet.StaticInput{
			Config:  cfg,
			Sourced: sourced,
			Realms:  configvet.RealmRegistry(sourced.Realms),
		})

		switch vetFormat {
		case "json":
			if err := configvet.RenderJSON(os.Stdout, report); err != nil {
				return err
			}
		case "text", "":
			configvet.RenderText(os.Stdout, report, !color.NoColor)
		default:
			return fmt.Errorf("unknown --format %q (want text or json)", vetFormat)
		}

		if report.HasErrors() || (vetStrict && len(report.Warnings()) > 0) {
			return BeQuietError{} // non-zero exit; findings already printed
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(configCmd)
	configCmd.AddCommand(configVetCmd)

	configVetCmd.Flags().BoolVar(&vetStrict, "strict", false, "treat warnings as errors")
	configVetCmd.Flags().StringVar(&vetFormat, "format", "text", "output format: text or json")
}
