package cmd

import (
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"github.com/darmiel/talmi/internal/config"
)

// configValidateCmd represents the config validate command
var configValidateCmd = &cobra.Command{
	Use:   "validate",
	Short: "Validate the configuration file",
	Long:  "", // TODO
	RunE: func(cmd *cobra.Command, args []string) error {
		_, err := config.Load(cfgFile)
		if err != nil {
			log.Fatal().Err(err).Msg("Configuration is invalid.")
			return err
		}
		log.Info().Msg("Configuration is valid.")
		return nil
	},
}

func init() {
	configCmd.AddCommand(configValidateCmd)
}
