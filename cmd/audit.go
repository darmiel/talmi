package cmd

import (
	"github.com/spf13/cobra"
)

// auditCmd represents the audit command
var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Check the audit log and view active tokens",
	Long:  "", // TODO
}

func init() {
	rootCmd.AddCommand(auditCmd)
}
