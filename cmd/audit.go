package cmd

import (
	"time"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/spf13/cobra"

	"github.com/darmiel/talmi/internal/cli"
	"github.com/darmiel/talmi/internal/cli/ui"
	"github.com/darmiel/talmi/internal/core"
	"github.com/darmiel/talmi/pkg/client"
)

func newAuditCmd(deps Deps) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Query the Talmi audit log",
	}
	cmd.AddCommand(newAuditListCmd(deps), newAuditInspectCmd(deps))
	return cmd
}

func newAuditListCmd(deps Deps) *cobra.Command {
	var (
		limit       int
		action      string
		principal   string
		fingerprint string
		since       string
		until       string
		requestID   string
		sessionID   string
		outcome     string
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
	cmd.Flags().StringVar(&until, "until", "", "only entries at/before this RFC3339 time")
	cmd.Flags().StringVar(&requestID, "request-id", "", "filter by request (correlation) id")
	cmd.Flags().StringVar(&sessionID, "session-id", "", "filter by session id")
	cmd.Flags().StringVar(&outcome, "outcome", "", "filter by outcome (success, failure, denied)")

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
			Until:       until,
			RequestID:   requestID,
			SessionID:   sessionID,
			Outcome:     outcome,
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

func newAuditInspectCmd(deps Deps) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "inspect <id>",
		Short: "Show a single audit entry (requires a session with talmi:audit=read)",
		Args:  cobra.ExactArgs(1),
	}
	jsonOut := addJSONFlag(cmd)
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		id := args[0]
		if id == "" {
			return cli.Fail(cli.CodeUsage, "audit inspect requires an audit entry id").
				Hint("Use 'talmi audit list' to find an entry id")
		}
		c, err := deps.NewClient()
		if err != nil {
			return err
		}
		event, correlation, err := c.InspectAudit(cmd.Context(), id)
		if err != nil {
			return clientError(err, correlation)
		}
		if *jsonOut {
			return emitJSON(deps, event)
		}
		who := ""
		if event.Actor != nil {
			who = event.Actor.ID
		}
		p := ui.New(deps.IO.Out, deps.IO.Color)
		p.Printf("%s  %s  %s\n", event.ID, string(event.Action), string(event.Outcome))
		p.Faintln("time=%s request=%s session=%s rev=%s",
			event.Time.Local().Format(time.RFC3339), event.RequestID, event.SessionID, event.Revision)
		p.Printf("principal: %s\n", who)
		if event.Error != "" {
			p.Printf("error: %s\n", event.Error)
		}
		for _, a := range event.Artifacts {
			p.Printf("artifact %s provider=%s fp=%s\n", a.ArtifactID, a.Provider, a.Fingerprint)
		}
		if event.Decision != nil {
			renderDecision(deps, *event.Decision)
		}
		return nil
	}
	return cmd
}
