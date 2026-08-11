package cmd

import (
	"time"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/spf13/cobra"

	"github.com/darmiel/talmi/internal/cli/ui"
)

func newTasksCmd(deps Deps) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "tasks",
		Aliases: []string{"task"},
		Short:   "Inspect and trigger background tasks (requires admin session)",
	}
	cmd.AddCommand(
		newTaskListCmd(deps),
		newTaskTriggerCmd(deps),
		newTaskLogsCmd(deps),
	)
	return cmd
}

func newTaskListCmd(deps Deps) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List background tasks and their status",
		Args:    cobra.NoArgs,
	}
	jsonOut := addJSONFlag(cmd)
	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		cli, err := deps.NewClient()
		if err != nil {
			return err
		}
		tasks, correlation, err := cli.ListTasks(cmd.Context())
		if err != nil {
			return clientError(err, correlation)
		}
		if *jsonOut {
			return emitJSON(deps, tasks)
		}
		if len(tasks) == 0 {
			ui.New(deps.IO.ErrOut, deps.IO.Color).Successln("no tasks found")
			return nil
		}
		tw := ui.NewTable(deps.IO.Out)
		tw.AppendHeader(table.Row{"Name", "Status", "Last Run", "Result", "Next Run"})
		for _, t := range tasks {
			tw.AppendRow(table.Row{t.Name, t.Running, fmtTime(t.LastRun), t.LastResult, fmtTime(t.NextRun)})
		}
		tw.Render()
		return nil
	}
	return cmd
}

func newTaskTriggerCmd(deps Deps) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "trigger NAME",
		Short: "Manually trigger a background task now",
		Args:  cobra.ExactArgs(1),
	}
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		cli, err := deps.NewClient()
		if err != nil {
			return err
		}
		correlation, err := cli.TriggerTask(cmd.Context(), args[0])
		if err != nil {
			return clientError(err, correlation)
		}
		ui.New(deps.IO.ErrOut, deps.IO.Color).Successln("triggered task %q", args[0])
		return nil
	}
	return cmd
}

func newTaskLogsCmd(deps Deps) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "logs NAME",
		Short: "Show the most recent logs of a background task",
		Args:  cobra.ExactArgs(1),
	}
	jsonOut := addJSONFlag(cmd)
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		cli, err := deps.NewClient()
		if err != nil {
			return err
		}
		logs, correlation, err := cli.TaskLogs(cmd.Context(), args[0])
		if err != nil {
			return clientError(err, correlation)
		}
		if *jsonOut {
			return emitJSON(deps, logs)
		}
		if len(logs) == 0 {
			ui.New(deps.IO.ErrOut, deps.IO.Color).Successln("no logs found for task %q", args[0])
			return nil
		}
		p := ui.New(deps.IO.Out, deps.IO.Color)
		for _, l := range logs {
			p.Printf("%s [%s] %s\n", l.Time.Local().Format(time.Kitchen), l.Level, l.Message)
		}
		return nil
	}
	return cmd
}

func fmtTime(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.Local().Format(time.RFC3339)
}
