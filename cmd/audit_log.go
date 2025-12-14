package cmd

import (
	"os"
	"time"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var (
	auditLogLimit uint
)

var auditLogCmd = &cobra.Command{
	Use:     "log",
	Short:   "Retrieve and display audit log entries",
	Long:    `Fetches the most recent decision logs from the server, including allowed and denied requests`,
	Example: `  talmi audit log --limit 50`,
	RunE: func(cmd *cobra.Command, args []string) error {
		cli, err := getClient()
		if err != nil {
			return err
		}

		log.Info().Msg("Fetching audit log...")
		audits, err := cli.ListAudits(cmd.Context(), auditLogLimit)
		if err != nil {
			return err
		}

		log.Info().Msgf("Retrieved %d audit entries", len(audits))

		t := table.NewWriter()
		t.SetOutputMirror(os.Stdout)
		t.AppendHeader(table.Row{
			"Time", "Action", "Principal", "Granted", "Provider", "Error",
		})

		for _, e := range audits {
			status := "YES"
			if !e.Granted {
				status = "NO"
			}

			sub := "(unknown)"
			if e.Principal != nil {
				sub = truncate(e.Principal.ID, 35)
			}

			t.AppendRow(table.Row{
				e.Time.Format(time.RFC3339),
				e.Action,
				sub,
				status,
				e.Provider,
				e.Error,
			})
		}

		t.SetStyle(table.StyleLight)
		t.Render()
		return nil
	},
}

func init() {
	auditCmd.AddCommand(auditLogCmd)

	auditLogCmd.Flags().UintVarP(&auditLogLimit, "limit", "n", 25, "Number of entries")
}
