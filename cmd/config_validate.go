package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/darmiel/talmi/internal/config"
)

var configValidateCmd = &cobra.Command{
	Use:     "validate",
	Short:   "Validate syntax of a Talmi configuration file",
	Example: `  talmi config validate talmi.yaml`,
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		path := args[0]
		if path == "" {
			return fmt.Errorf("configuration file path cannot be empty")
		}
		_, err := config.Load(path)
		if err != nil {
			return logError(err, "", "configuration validation failed")
		}
		logSuccess("configuration is valid")
		return nil
	},
}

func init() {
	configCmd.AddCommand(configValidateCmd)
}
