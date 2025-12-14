package cmd

import (
	"github.com/spf13/cobra"
)

var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Administrative audit commands",
	Long:  `View audit logs and inspect active tokens on the server. Requires an authenticated session (talmi login).`,
}

func init() {
	rootCmd.AddCommand(auditCmd)
}
