package cmd

import (
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"github.com/darmiel/talmi/internal/config"
)

var configValidateConfig string

var configValidateCmd = &cobra.Command{
	Use:     "validate",
	Short:   "Validate syntax of a Talmi configuration file",
	Example: `  talmi config validate -f talmi.yaml`,
	RunE: func(cmd *cobra.Command, args []string) error {
		_, err := config.Load(configValidateConfig)
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

	configValidateCmd.Flags().StringVarP(&configValidateConfig, "config", "f", "", "Path to Talmi configuration file")
	_ = configValidateCmd.MarkFlagRequired("config")
}
