package cmd

import (
	"errors"
	"fmt"
	"net/url"
	"os"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"github.com/darmiel/talmi/internal/cliconfig"
	"github.com/darmiel/talmi/pkg/client"
)

var (
	loginToken     string
	loginServerURL string
	loginIssuer    string
)

const (
	tokenEnvVar     = "TALMI_TOKEN"
	serverURLEnvVar = "TALMI_ADDR"
)

// loginCmd represents the logincommand
var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Authenticate with Talmi and save credentials",
	// Long: "", // TODO
	RunE: func(cmd *cobra.Command, args []string) error {
		if loginToken == "" {
			loginToken = os.Getenv(tokenEnvVar)
		}
		if loginToken == "" {
			return fmt.Errorf("upstream token provided, (via --token or %s)", tokenEnvVar)
		}

		if loginServerURL == "" {
			loginServerURL = os.Getenv(serverURLEnvVar)
		}
		if loginServerURL == "" {
			return fmt.Errorf("server address must be provided (via --addr or %s)", serverURLEnvVar)
		}

		u, err := url.Parse(loginServerURL)
		if err != nil {
			return fmt.Errorf("parsing server URL: %w", err)
		}

		// perform exchange via client
		cli := client.New(loginServerURL)

		log.Info().Msgf("Issuing token from server %q...", u.Host)

		artifact, err := cli.IssueToken(cmd.Context(), loginToken, client.IssueTokenOptions{
			RequestedProvider: "talmi",
			RequestedIssuer:   loginIssuer,
		})
		if err != nil {
			return fmt.Errorf("issuing token: %w", err)
		}

		cfg, err := cliconfig.Load()
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("loading config: %w", err)
			}
			cfg = &cliconfig.CLIConfig{}
		}
		if cfg.Credentials == nil {
			cfg.Credentials = make(map[string]*cliconfig.Credential)
		}
		cfg.Credentials[u.Host] = &cliconfig.Credential{
			Token: artifact.Value,
		}
		if err := cliconfig.Save(cfg); err != nil {
			return fmt.Errorf("saving config: %w", err)
		}

		log.Info().Msgf("Credentials for server %q saved successfully", u.Host)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(loginCmd)

	loginCmd.Flags().StringVar(&loginServerURL, "server", "", "Talmi Server URL")
	loginCmd.Flags().StringVar(&loginIssuer, "issuer", "", "Upstream Issuer Name")
	loginCmd.Flags().StringVar(&loginToken, "token", "", "Upstream Token")
}
