package cmd

import (
	"fmt"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"github.com/darmiel/talmi/pkg/client"
)

var (
	revokeToken string
	revokeAuth  string
)

var revokeCmd = &cobra.Command{
	Use:   "revoke",
	Short: "Revoke an issued token",
	Long: `Invalidates a downstream token immediately.
Requires the 'revocation_token' provided during issurance.`,
	Example: `  # Revoke using the revocation token
  talmi revoke --token <original-token> --auth <revocation-token>`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if revokeToken == "" {
			return fmt.Errorf("must provide --token")
		}
		if revokeAuth == "" {
			return fmt.Errorf("must provide --auth")
		}
		server, err := f.GetRemoteAddr()
		if err != nil {
			return err
		}
		cli := client.New(server, client.WithAuthToken(revokeAuth))
		correlation, err := cli.RevokeToken(cmd.Context(), revokeToken)
		if err != nil {
			log.Error().Msgf("%s failed to revoke token (correlation ID: %s)", redCross, correlation)
			log.Error().Msgf("error: %v", err)
			return BeQuietError{}
		}

		log.Info().Msgf("%s token revoked successfully", greenCheck)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(revokeCmd)
	revokeCmd.Flags().StringVar(&revokeToken, "token", "", "The original issued token to revoke")
	revokeCmd.Flags().StringVar(&revokeAuth, "auth", "", "The revocation token provided during issuance")
	_ = revokeCmd.MarkFlagRequired("token")
	_ = revokeCmd.MarkFlagRequired("auth")
}
