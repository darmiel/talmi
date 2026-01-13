package cmd

import (
	"errors"
	"fmt"
	"net/url"
	"os"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/darmiel/talmi/internal/cliconfig"
	"github.com/darmiel/talmi/pkg/client"
)

var (
	loginToken  string
	loginIssuer string
)

var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Authenticate with a Talmi server",
	Long: `Exchanges an upstream OIDC token (e.g., from GitHub Actions) for a Talmi Session Token.
The session token is saved locally to allow future authenticated requests (like audit logs).`,
	Example: `  talmi login --server https://talmi.example.com --token <upstream-oidc-token>`,
	RunE: func(cmd *cobra.Command, args []string) error {
		server := viper.GetString(TalmiAddrKey)
		if server == "" {
			return fmt.Errorf("server address not configured, provide via --server or env")
		}

		u, err := url.Parse(server)
		if err != nil {
			return fmt.Errorf("parsing server URL: %w", err)
		}

		// perform exchange via client
		cli := client.New(server)

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

	loginCmd.Flags().StringVarP(&loginToken, "token", "t", "", "Upstream Token")
	loginCmd.Flags().StringVar(&loginIssuer, "issuer", "", "Upstream Issuer Name (optional)")

	_ = loginCmd.MarkFlagRequired("token")
}
