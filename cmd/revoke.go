package cmd

import (
	"fmt"

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
		if revokeAuth == "" {
			return fmt.Errorf("must provide --auth")
		}
		// note that we are not checking for empty revokeToken here,
		// because only some providers need the original token,
		// which we cannot store.
		server, err := f.GetRemoteAddr()
		if err != nil {
			return err
		}
		cli := client.New(server, client.WithAuthToken(revokeAuth))
		correlation, err := cli.RevokeToken(cmd.Context(), revokeToken)
		if err != nil {
			return logError(err, correlation, "failed to revoke token")
		}

		logSuccess("token revoked successfully")
		return nil
	},
}

func init() {
	rootCmd.AddCommand(revokeCmd)
	revokeCmd.Flags().StringVar(&revokeToken, "token", "", "Some providers may require the original token to revoke")
	revokeCmd.Flags().StringVar(&revokeAuth, "auth", "", "The revocation token provided during issuance")
	_ = revokeCmd.MarkFlagRequired("auth")
}
