package cmd

import (
	"fmt"
	"os"
	"time"

	"github.com/fatih/color"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var auditTokensCmd = &cobra.Command{
	Use:   "tokens",
	Short: "List currently active tokens",
	Long: `Retrieves a list of all currently active (non-expired) tokens issued by the server.
This includes details such as the principal who requested it, the provider used, and expiration time.

This command requires an authenticated session (via 'talmi login') with admin privileges.`,
	Example: `  talmi audit tokens`,
	RunE: func(cmd *cobra.Command, args []string) error {
		cli, err := getClient()
		if err != nil {
			return err
		}

		log.Debug().Msg("Fetching active tokens...")
		tokens, err := cli.ListActiveTokens(cmd.Context())
		if err != nil {
			return err
		}

		if len(tokens) == 0 {
			log.Info().Msg("No active tokens found")
			return nil
		}
		log.Debug().Msgf("Retrieved %d active token(s)", len(tokens))

		t := table.NewWriter()
		t.SetOutputMirror(os.Stdout)
		t.AppendHeader(table.Row{
			"Issued", "Expires", "Principal", "Provider", "Policy", "Meta",
		})

		bold := color.New(color.Bold).SprintFunc()
		faint := color.New(color.Faint).SprintfFunc()

		for _, tok := range tokens {
			timeLeft := time.Until(tok.ExpiresAt).Round(time.Minute)

			metaStr := "(empty)"
			if tok.Metadata != nil {
				metaStr = fmt.Sprintf("(%d entries)", len(tok.Metadata))
			}
			sub := truncate(tok.PrincipalID, 64)
			t.AppendRow(table.Row{
				tok.IssuedAt.Format(time.RFC3339),
				fmt.Sprintf("%s (%s)", tok.ExpiresAt.Format("15:04"), faint(timeLeft.String())),
				bold(sub),
				tok.Provider,
				bold(tok.PolicyName),
				faint(metaStr),
			})
		}

		s := table.StyleRounded
		s.Format.Header = text.FormatDefault
		t.SetStyle(s)
		t.Render()
		return nil
	},
}

func init() {
	auditCmd.AddCommand(auditTokensCmd)
}
