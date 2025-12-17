package cmd

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/darmiel/talmi/internal/buildinfo"
	"github.com/darmiel/talmi/internal/logging"
)

// global flags
var (
	userConfig string
	talmiAddr  string
)

const (
	LogLevelKey   = "log.level"
	LogFormatKey  = "log.format"
	LogNoColorKey = "log.no_color"

	TalmiAddrKey = "addr"
)

var rootCmd = &cobra.Command{
	Use:   "talmi",
	Short: fmt.Sprintf("Talmi STS (version: %s, commit: %s)", buildinfo.Version, buildinfo.CommitHash),
	Long: `Talmi is a minimal, extensible Security Token Service (STS).
	It grants access to downstream resources (like GitHub Apps, Cloud Providers)
	based on verified identities from upstream IdPs (like OIDC).`,
	Version: buildinfo.Version,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		configPath, configErr := initConfig()
		logging.Init(nil)
		if configErr != nil { // handle error after logging is initialized
			return configErr
		}
		if configPath != "" {
			log.Debug().Msgf("using config file: %s", configPath)
		}
		return nil
	},
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		log.Fatal().Err(err).Msg("execution failed")
		os.Exit(1)
	}
}

func init() {
	// setup pre-flag logger
	logging.InitDefault()

	rootCmd.PersistentFlags().StringVar(&userConfig, "user-config", "",
		"User configuration file for default values (default is $HOME/.talmi.yaml)")

	rootCmd.PersistentFlags().String("log-level", "info", "Log level (debug, info, warn, error)")
	_ = viper.BindPFlag(LogLevelKey, rootCmd.PersistentFlags().Lookup("log-level"))

	rootCmd.PersistentFlags().String("log-format", "console", "Log format (console, json)")
	_ = viper.BindPFlag(LogFormatKey, rootCmd.PersistentFlags().Lookup("log-format"))

	rootCmd.PersistentFlags().Bool("no-color", false, "Disable color output")
	_ = viper.BindPFlag(LogNoColorKey, rootCmd.PersistentFlags().Lookup("no-color"))

	rootCmd.PersistentFlags().StringVar(&talmiAddr, "server", "", "Address of the remote Talmi server")
	_ = viper.BindPFlag(TalmiAddrKey, rootCmd.PersistentFlags().Lookup("server"))

	viper.SetEnvPrefix("TALMI")
	viper.SetEnvKeyReplacer(strings.NewReplacer(
		".", "_",
		"-", "_",
	))

	viper.AutomaticEnv()

	rootCmd.SilenceUsage = true
	rootCmd.SilenceErrors = true
}

func initConfig() (string, error) {
	// reads in config file and ENV variables if set.
	if userConfig != "" {
		viper.SetConfigFile(userConfig)
	} else {
		// search order: current dir, $HOME, XDG config
		viper.AddConfigPath(".")

		home, err := os.UserHomeDir()
		if err == nil {
			viper.AddConfigPath(home)
		}

		config, err := os.UserConfigDir()
		if err == nil {
			viper.AddConfigPath(config + "/talmi")
		}

		viper.SetConfigType("yaml")
		viper.SetConfigName(".talmi")
	}

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err != nil {
		var notFoundError viper.ConfigFileNotFoundError
		if !errors.As(err, &notFoundError) {
			return "", err
		}
	} else {
		return viper.ConfigFileUsed(), nil
	}

	return "", nil
}
