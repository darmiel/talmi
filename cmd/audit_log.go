package cmd

import (
	"os"
	"time"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

// auditLogCmd represents the audit command
var auditLogCmd = &cobra.Command{
	Use:   "log",
	Short: "Retrieve and display audit log entries",
	Long:  "", // TODO
	RunE: func(cmd *cobra.Command, args []string) error {
		limit, err := cmd.Flags().GetInt("limit")
		if err != nil {
			return err
		}

		cli, err := getClient()
		if err != nil {
			return err
		}

		log.Info().Msg("Fetching audit log...")
		audits, err := cli.ListAudits(cmd.Context(), uint(limit))
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

	auditLogCmd.Flags().IntP("limit", "n", 25, "Number of audit entries to retrieve")
}
