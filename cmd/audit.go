package cmd

import (
	"encoding/json"
	"os"
	"time"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/spf13/cobra"

	"github.com/darmiel/talmi/pkg/client"
)

var (
	auditLimit       int
	auditAction      string
	auditPrincipal   string
	auditFingerprint string
	auditSince       string
	auditJSON        bool
)

var auditCmd = &cobra.Command{
	Use: "audit",
	Short: `Query the Talmi audit log. Filter by action, principal, fingerprint, time and limit.
Requires 'talmi login' with a session that has talmi:audit read.`,
	RunE: func(cmd *cobra.Command, _ []string) error {
		cli, err := f.GetClient()
		if err != nil {
			return err
		}
		entries, correlation, err := cli.QueryAudit(cmd.Context(), client.AuditFilter{
			Limit:       auditLimit,
			Action:      auditAction,
			Fingerprint: auditFingerprint,
			PrincipalID: auditPrincipal,
			Since:       auditSince,
		})
		if err != nil {
			return logError(err, correlation, "could not query audit log")
		}

		if auditJSON {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(entries)
		}

		if len(entries) == 0 {
			logSuccess("no audit entries match")
			return nil
		}

		tw := table.NewWriter()
		applyTableFormat(tw)
		tw.SetOutputMirror(os.Stdout)
		tw.AppendHeader(table.Row{"Time", "Correlation", "Principal", "Action", "Result", "Policy@Rev"})
		for _, e := range entries {
			principal := ""
			if e.Principal != nil {
				principal = e.Principal.ID
			}
			result := greenCheck
			if !e.Success {
				result = redCross + " " + e.Error
			}
			tw.AppendRow(table.Row{
				e.Time.Local().Format(time.RFC3339),
				e.ID, principal, e.Action, result, e.Revision,
			})
		}
		tw.Render()
		return nil
	},
}

func init() {
	rootCmd.AddCommand(auditCmd)
	auditCmd.Flags().IntVar(&auditLimit, "limit", 50, "Maximum number of entries")
	auditCmd.Flags().StringVar(&auditAction, "action", "", "Filter by action (e.g. lease.issue, lease.revoke)")
	auditCmd.Flags().StringVar(&auditPrincipal, "principal", "", "Filter by principal id")
	auditCmd.Flags().StringVar(&auditFingerprint, "fingerprint", "", "Filter by minted token fingerprint")
	auditCmd.Flags().StringVar(&auditSince, "since", "", "Only entries at/after this RFC3339 time")
	auditCmd.Flags().BoolVar(&auditJSON, "json", false, "Output raw JSON instead of a table")
}
