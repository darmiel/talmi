package cmd

import (
	"fmt"

	"github.com/fatih/color"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var tasksTriggerCmd = &cobra.Command{
	Use:   "trigger NAME",
	Short: "Manually trigger a background task",
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

		log.Debug().Msgf("Triggering tasks '%s'...", name)
		if err := cli.TriggerTask(cmd.Context(), name); err != nil {
			return fmt.Errorf("triggering task: %w", err)
		}

		log.Info().Msgf("%s triggered task '%s' successfully.",
			greenCheck, color.New(color.Bold).Sprint(name))
		log.Info().Msgf("Run '%s' to see progress.", color.CyanString("talmi tasks logs "+name))
		return nil
	},
}

func init() {
	tasksCmd.AddCommand(tasksTriggerCmd)
}
