package cmd

import (
	"github.com/spf13/cobra"
)

// tokenCmd represents the token command
var tokenCmd = &cobra.Command{
	Use:   "token",
	Short: "Interact with tokens",
	Long:  "", // TODO
}

func init() {
	rootCmd.AddCommand(tokenCmd)
}
