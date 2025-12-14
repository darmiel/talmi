package cmd

import (
	"github.com/spf13/cobra"
)

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Interact with the configuration",
	Long:  `Utilities for validating and viewing the Talmi configuration`,
}

func init() {
	rootCmd.AddCommand(configCmd)
}
