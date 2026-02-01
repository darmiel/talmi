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
	"github.com/darmiel/talmi/internal/core"
	talmiprovider "github.com/darmiel/talmi/internal/providers/talmi"
	"github.com/darmiel/talmi/pkg/client"
)

var (
	loginIssuer     string
	loginTargetKind string
)

var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Authenticate with a Talmi server",
	Long: `Exchanges an upstream OIDC token (e.g., from GitHub Actions) for a Talmi Session Token.
The session token is saved locally to allow future authenticated requests (like audit logs).`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		loginToken := args[0]
		if loginToken == "" {
			return fmt.Errorf("token cannot be empty")
		}

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

		artifact, correlationID, err := cli.IssueToken(cmd.Context(), loginToken, client.IssueTokenOptions{
			RequestedTargets: []core.Target{
				{
					Kind:     loginTargetKind,
					Resource: "?",
				},
			},
			RequestedIssuer: loginIssuer,
		})
		if err != nil {
			log.Error().Msgf("%s failed to issue token (correlation ID: %s)", redCross, correlationID)
			log.Error().Msgf("error: %v", err)
			return BeQuietError{}
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
			return logError(err, "", "login succeeded but could not save credentials")
		}

		logSuccess("saved credentials for %s", bold(u.Host))
		return nil
	},
}

func init() {
	rootCmd.AddCommand(loginCmd)

	loginCmd.Flags().StringVar(&loginIssuer, "issuer", "", "Upstream Issuer Name (optional)")
	loginCmd.Flags().StringVar(&loginTargetKind, "target-kind", talmiprovider.DefaultKind, "Target Kind to request (optional)")

	_ = loginCmd.MarkFlagRequired("token")
}
