package cmd

import (
	"os"
	"time"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"github.com/darmiel/talmi/internal/core"
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

		log.Info().Msg("Fetching audit log...")

		// TODO: request from server
		_ = limit
		var audits = []core.AuditEntry{
			{
				ID:      "test",
				Time:    time.Now(),
				Action:  "issue_token",
				Granted: true,
			},
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
				sub := e.Principal.ID
				if len(sub) > 20 {
					sub = sub[:17] + "..."
				}
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
