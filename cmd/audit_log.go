package cmd

import (
	"os"
	"time"

	"github.com/fatih/color"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"github.com/darmiel/talmi/pkg/client"
)

var (
	auditLogLimit       uint
	auditLogPrincipal   string
	auditLogFingerprint string
)

var auditLogCmd = &cobra.Command{
	Use:   "log",
	Short: "Retrieve and display audit log entries",
	Long:  `Fetches the most recent decision logs from the server, including allowed and denied requests`,
	Example: `  # Retrieve 50 most recent audit log entries
  talmi audit log --limit 50
  
  # Retrieve audit log entries for a specific fingerprint
  talmi audit log --fingerprint xA+LGEy4r8==`,
	RunE: func(cmd *cobra.Command, args []string) error {
		cli, err := f.GetClient()
		if err != nil {
			return err
		}

		log.Debug().Msg("Fetching audit log...")
		audits, correlation, err := cli.ListAudits(cmd.Context(), client.ListAuditsOpts{
			Limit:       auditLogLimit,
			PrincipalID: auditLogPrincipal,
			Fingerprint: auditLogFingerprint,
		})
		if err != nil {
			return logError(err, correlation, "failed to retrieve audit log entries")
		}

		if len(audits) == 0 {
			log.Info().Msg("No audit log entries found")
			return nil
		}
		log.Debug().Msgf("Retrieved %d audit entries", len(audits))

		t := table.NewWriter()
		t.SetOutputMirror(os.Stdout)
		t.AppendHeader(table.Row{
			"Time", "Correlation ID", "Principal", "Action",
		})

		green := color.New(color.FgGreen).SprintFunc()
		red := color.New(color.FgRed).SprintFunc()

		for _, e := range audits {
			subRaw := "(unknown)"
			sub := faint(subRaw)
			if e.Principal != nil {
				subRaw = truncate(e.Principal.ID, 64)
				sub = bold(subRaw)
			}

			var success string
			if e.Success {
				success = green("✔")
			} else {
				success = red("✖")
				sub = red(subRaw) // make it red!
			}

			t.AppendRow(table.Row{
				e.Time.Format(time.RFC3339),
				e.ID,
				sub,
				success + " " + e.Action,
			})
		}

		applyTableFormat(t)
		t.Render()
		return nil
	},
}

func init() {
	auditCmd.AddCommand(auditLogCmd)

	auditLogCmd.Flags().UintVarP(&auditLogLimit, "limit", "n", 25, "Number of entries")
	auditLogCmd.Flags().StringVarP(&auditLogPrincipal, "principal", "p", "", "Filter by principal ID")
	auditLogCmd.Flags().StringVarP(&auditLogFingerprint, "fingerprint", "f", "", "Filter by token fingerprint")
}
