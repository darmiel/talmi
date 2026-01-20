package cmd

import (
	"fmt"
	"os"
	"time"

	"github.com/fatih/color"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var tasksListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List all background tasks",
	RunE: func(cmd *cobra.Command, args []string) error {
		cli, err := f.GetClient()
		if err != nil {
			return err
		}

		log.Debug().Msg("Retrieving tasks...")
		tasks, err := cli.ListTasks(cmd.Context())
		if err != nil {
			return fmt.Errorf("listing tasks: %w", err)
		}

		t := table.NewWriter()
		t.SetOutputMirror(os.Stdout)
		t.AppendHeader(table.Row{"Name", "State", "Last Run", "Next Run", "Last Result"})

		for _, task := range tasks {
			state := "idle"
			if task.Running {
				state = color.BlueString("running")
			}

			lastRun := "never"
			if !task.LastRun.IsZero() {
				lastRun = time.Since(task.LastRun).Round(time.Second).String() + " ago"
			}

			nextRun := "n/a"
			if !task.NextRun.IsZero() {
				nextRun = "in " + time.Until(task.NextRun).Round(time.Second).String()
			}

			prefix := ""
			if task.LastResult == "success" {
				prefix = greenCheck
			} else if task.LastResult != "" {
				prefix = redCross
			}

			t.AppendRow(table.Row{
				color.New(color.Bold).Sprint(task.Name),
				state,
				lastRun,
				nextRun,
				prefix + " " + task.LastResult,
			})
		}

		applyTableFormat(t)
		t.Render()
		return nil
	},
}

func init() {
	tasksCmd.AddCommand(tasksListCmd)
}
