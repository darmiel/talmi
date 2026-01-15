package cmd

import (
	"fmt"

	"github.com/fatih/color"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var tasksLogsCmd = &cobra.Command{
	Use:   "logs NAME",
	Short: "See logs of a background task",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]
		if name == "" {
			return fmt.Errorf("task name cannot be empty")
		}

		cli, err := f.GetClient()
		if err != nil {
			return err
		}

		log.Debug().Msgf("Retrieving logs for task '%s'...", name)
		logs, err := cli.GetTaskLogs(cmd.Context(), name)
		if err != nil {
			return fmt.Errorf("retrieving task logs: %w", err)
		}

		log.Info().Msgf("Logs for task '%s':", name)
		fmt.Println("----------------------------------------")
		for _, entry := range logs {
			ts := entry.Time.Format("15:04:05")

			level := entry.Level
			switch entry.Level {
			case "info":
				level = color.GreenString("inf")
			case "warn":
				level = color.YellowString("wrn")
			case "error":
				level = color.RedString("err")
			case "debug":
				level = color.New(color.Faint).Sprint("dbg")
			default:
				level = entry.Level
			}

			fmt.Printf("%s | %s | %s\n", ts, level, entry.Message)
		}
		return nil
	},
}

func init() {
	tasksCmd.AddCommand(tasksLogsCmd)
}
