package cmd

import (
	"github.com/spf13/cobra"
)

// configCmd represents the config command
var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Interact with the configuration",
	Long:  "", // TODO
}

func init() {
	rootCmd.AddCommand(configCmd)
}
