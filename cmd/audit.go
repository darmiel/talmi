package cmd

import (
	"time"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/spf13/cobra"

	"github.com/darmiel/talmi/internal/cli/ui"
	"github.com/darmiel/talmi/internal/core"
	"github.com/darmiel/talmi/pkg/client"
)

func newAuditCmd(deps Deps) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Query the Talmi audit log",
	}
	cmd.AddCommand(newAuditListCmd(deps))
	return cmd
}

func newAuditListCmd(deps Deps) *cobra.Command {
	var (
		limit       int
		action      string
		principal   string
		fingerprint string
		since       string
	)

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List audit entries (requires a session with talmi:audit=read)",
		Args:  cobra.NoArgs,
	}

	jsonOut := addJSONFlag(cmd)
	cmd.Flags().IntVar(&limit, "limit", 50, "maximum number of entries")
	cmd.Flags().StringVar(&action, "action", "", "filter by action (e.g. lease.issue, lease.revoke)")
	cmd.Flags().StringVar(&principal, "principal", "", "filter by principal id")
	cmd.Flags().StringVar(&fingerprint, "fingerprint", "", "filter by minted token fingerprint")
	cmd.Flags().StringVar(&since, "since", "", "only entries at/after this RFC3339 time")

	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		cli, err := deps.NewClient()
		if err != nil {
			return err
		}
		entries, correlation, err := cli.QueryAudit(cmd.Context(), client.AuditFilter{
			Limit:       limit,
			Action:      action,
			Fingerprint: fingerprint,
			ActorID:     principal,
			Since:       since,
		})
		if err != nil {
			return clientError(err, correlation)
		}
		if *jsonOut {
			return emitJSON(deps, entries)
		}
		if len(entries) == 0 {
			ui.New(deps.IO.ErrOut, deps.IO.Color).Successln("no audit entries match")
			return nil
		}

		tw := ui.NewTable(deps.IO.Out)
		tw.AppendHeader(table.Row{"Time", "Request", "Principal", "Action", "Result", "Rev"})
		for _, e := range entries {
			who := ""
			if e.Actor != nil {
				who = e.Actor.ID
			}
			result := "\u2713"
			if e.Outcome != core.OutcomeSuccess {
				result = "\u2717 " + string(e.Outcome)
				if e.Error != "" {
					result += ": " + e.Error
				}
			}
			tw.AppendRow(table.Row{
				e.Time.Local().Format(time.RFC3339),
				e.RequestID, who, string(e.Action), result, e.Revision,
			})
		}
		tw.Render()
		return nil
	}
	return cmd
}
