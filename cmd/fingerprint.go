package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"github.com/darmiel/talmi/internal/audit"
)

var (
	fingerprintProviderType string
	fingerprintRaw          bool
)

var fingerprintCmd = &cobra.Command{
	Use:     "fingerprint [token]",
	Aliases: []string{"fp"},
	Short:   `Calculate the fingerprint of a token`,
	Long: `Calculates the unique fingerprint of a token based on the provider's algorithm.
This is the value stored in Talmi's audit logs in the 'token_fingerprint' field.

Different providers use different algorithms:
- default:    (no fingerprint)
- github: SHA256 -> Base64 (Matches GitHub Audit Log)
- talmi_jwt:  (same as github)`,
	Example: `  # Calculate GitHub fingerprint of a token
  talmi fingerprint --type github ghs_123456...

  # Calculate fingerprint of a token from stdin
  echo "ghs_..." | talmi utils fingerprint --type github -`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		var token string

		if args[0] != "-" {
			token = args[0]
		} else {
			// read from stdin
			log.Debug().Msg("Reading token from stdin")

			data, err := os.ReadFile("/dev/stdin")
			if err != nil {
				return fmt.Errorf("failed to read token from stdin: %w", err)
			}
			token = strings.TrimSpace(string(data))
		}

		if token == "" {
			return fmt.Errorf("token cannot be empty")
		}

		fp := audit.CalculateFingerprint(fingerprintProviderType, token)

		if fingerprintRaw {
			fmt.Println(fp)
		} else {
			fmt.Println("Provider Type:", fingerprintProviderType)
			fmt.Println("Fingerprint:  ", fp)
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(fingerprintCmd)

	fingerprintCmd.Flags().StringVar(&fingerprintProviderType, "type", audit.DefaultFingerprintType,
		fmt.Sprintf("Provider type (one of: %s)", strings.Join(audit.RegisteredFingerprinterTypes(), ", ")))
	fingerprintCmd.Flags().BoolVarP(&fingerprintRaw, "raw", "r", false,
		"Output only the fingerprint value without additional text")
}
