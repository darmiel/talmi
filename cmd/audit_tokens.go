package cmd

import (
	"fmt"
	"os"
	"time"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

// auditTokensCmd represents the audit command
var auditTokensCmd = &cobra.Command{
	Use:   "tokens",
	Short: "Retrieve and display active tokens",
	Long:  "", // TODO
	RunE: func(cmd *cobra.Command, args []string) error {
		cli, err := getClient()
		if err != nil {
			return err
		}

		log.Info().Msg("Fetching active tokens...")

		tokens, err := cli.ListActiveTokens(cmd.Context())
		if err != nil {
			return err
		}

		log.Info().Msgf("Retrieved %d active tokens", len(tokens))

		t := table.NewWriter()
		t.SetOutputMirror(os.Stdout)
		t.AppendHeader(table.Row{
			"Issued", "Expires", "Principal", "Provider", "Meta",
		})

		for _, tok := range tokens {
			timeLeft := time.Until(tok.ExpiresAt).Round(time.Minute)

			metaStr := "(empty)"
			if tok.Metadata != nil {
				metaStr = fmt.Sprintf("(%d entries)", len(tok.Metadata))
			}

			t.AppendRow(table.Row{
				tok.IssuedAt.Format("15:04:05"),
				fmt.Sprintf("%s (%s left)", tok.ExpiresAt.Format("15:04"), timeLeft),
				tok.PrincipalID,
				tok.Provider,
				metaStr,
			})
		}

		t.SetStyle(table.StyleLight)
		t.Render()
		return nil
	},
}

func init() {
	auditCmd.AddCommand(auditTokensCmd)
}
