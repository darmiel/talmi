package cmd

import "github.com/spf13/cobra"

var debugCmd = &cobra.Command{
	Use:   "debug",
	Short: "Debugging commands",
	Long:  `Commands for debugging Talmi installations and configurations`,
}

func init() {
	rootCmd.AddCommand(debugCmd)
}
