package cmd

import (
	"fmt"
	"os"
	"time"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/spf13/cobra"
)

var tasksCmd = &cobra.Command{
	Use:     "tasks",
	Aliases: []string{"task"},
	Short:   "Inspect and trigger background tasks (requires admin session)",
}

var tasksListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List background tasks and their status",
	RunE: func(cmd *cobra.Command, _ []string) error {
		cli, err := f.GetClient()
		if err != nil {
			return err
		}
		tasks, correlation, err := cli.ListTasks(cmd.Context())
		if err != nil {
			return logError(err, correlation, "could not list tasks")
		}
		if len(tasks) == 0 {
			logSuccess("no tasks found")
			return nil
		}
		tw := table.NewWriter()
		applyTableFormat(tw)
		tw.SetOutputMirror(os.Stdout)
		tw.AppendHeader(table.Row{"Name", "Status", "Last Run", "Result", "Next Run"})
		for _, t := range tasks {
			tw.AppendRow(table.Row{t.Name, t.Running, fmtTime(t.LastRun), t.LastResult, fmtTime(t.NextRun)})
		}
		tw.Render()
		return nil
	},
}

var tasksTriggerCmd = &cobra.Command{
	Use:   "trigger NAME",
	Short: "Manually trigger a background task now",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cli, err := f.GetClient()
		if err != nil {
			return err
		}
		correlation, err := cli.TriggerTask(cmd.Context(), args[0])
		if err != nil {
			return logError(err, correlation, "could not trigger task")
		}
		logSuccess("triggered task %q", args[0])
		return nil
	},
}

var tasksLogsCmd = &cobra.Command{
	Use:   "logs NAME",
	Short: "Show the most recent logs of a background task",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cli, err := f.GetClient()
		if err != nil {
			return err
		}
		logs, correlation, err := cli.TaskLogs(cmd.Context(), args[0])
		if err != nil {
			return logError(err, correlation, "could not get task logs")
		}
		if len(logs) == 0 {
			logSuccess("no logs found for task %q", args[0])
			return nil
		}
		for _, l := range logs {
			fmt.Printf("%s %s %s\n", faint(l.Time.Local().Format(time.Kitchen)), bold("["+l.Level+"]"), l.Message)
		}
		return nil
	},
}

func fmtTime(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.Local().Format(time.RFC3339)
}

func init() {
	rootCmd.AddCommand(tasksCmd)
	tasksCmd.AddCommand(tasksListCmd, tasksTriggerCmd, tasksLogsCmd)
}
