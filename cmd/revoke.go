package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/darmiel/talmi/pkg/client"
)

var (
	revokeSecret    string
	revokeFromLease string
	revokeTokens    []string
)

var revokeCmd = &cobra.Command{
	Use:   "revoke",
	Short: "Revoke a previously issued lease",
	Long: `Revokes a lease. Provide --from-lease pointing at a lease.json written by
'talmi issue --out' (it carries the secret and token values), or pass --secret
and --token fingerprint=value flags directly.`,
	Example: `  talmi revoke --from-lease ./.talmi/out/lease.json
  talmi revoke --secret <secret> --token <fingerprint>=<token>`,
	RunE: func(cmd *cobra.Command, _ []string) error {
		server, err := f.GetRemoteAddr()
		if err != nil {
			return err
		}
		secret, tokens, err := gatherRevoke()
		if err != nil {
			return err
		}
		if secret == "" {
			return fmt.Errorf("no revocation secret provided (use --from-lease or --secret)")
		}

		resp, correlation, err := client.New(server).RevokeLease(cmd.Context(), secret, tokens)
		if err != nil {
			return logError(err, correlation, "revocation failed")
		}
		logSuccess("revoked lease %s (%d artifact(s))", resp.LeaseID, len(resp.Revoked))
		return nil
	},
}

func gatherRevoke() (string, map[string]string, error) {
	secret := revokeSecret
	tokens := make(map[string]string)

	if revokeFromLease != "" {
		data, err := os.ReadFile(revokeFromLease)
		if err != nil {
			return "", nil, fmt.Errorf("reading lease file: %w", err)
		}
		var lease client.IssueResponse
		if err := json.Unmarshal(data, &lease); err != nil {
			return "", nil, fmt.Errorf("parsing lease file: %w", err)
		}
		if secret == "" {
			secret = lease.RevocationSecret
		}
		for _, a := range lease.Artifacts {
			if a.Token != "" {
				tokens[a.Fingerprint] = a.Token
			}
		}
	}
	for _, tf := range revokeTokens {
		fp, tok, ok := strings.Cut(tf, "=")
		if !ok {
			return "", nil, fmt.Errorf("bad --token %q (want fingerprint=value)", tf)
		}
		tokens[fp] = tok
	}
	return secret, tokens, nil
}

func init() {
	rootCmd.AddCommand(revokeCmd)

	revokeCmd.Flags().StringVar(&revokeFromLease, "from-lease", "", "Path to a lease.json from 'talmi issue --out'")
	revokeCmd.Flags().StringVar(&revokeSecret, "secret", "", "Revocation secret")
	revokeCmd.Flags().StringArrayVar(&revokeTokens, "token", nil, "fingerprint=value (repeatable; for by-value providers)")
}
