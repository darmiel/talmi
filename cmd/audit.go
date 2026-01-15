package cmd

import (
	"github.com/spf13/cobra"
)

var tasksCmd = &cobra.Command{
	Use:     "tasks",
	Aliases: []string{"task"},
	Short:   "Manage background tasks and policies",
	Long:    `Inspect status, trigger runs, and view logs for background tasks (like policy sync).`,
}

func init() {
	rootCmd.AddCommand(tasksCmd)
}
