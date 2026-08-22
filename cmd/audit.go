package cmd

import (
	"bytes"
	"sort"
	"time"

	"github.com/spf13/cobra"

	"github.com/darmiel/talmi/internal/cli"
	"github.com/darmiel/talmi/internal/cli/ui"
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
		nodeID      string
		outcome     string
		noPager     bool
	)

	cmd := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls", "log"},
		Short:   "List audit entries (requires a session with talmi:audit=read)",
		Args:    cobra.NoArgs,
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
	cmd.Flags().StringVar(&nodeID, "node", "", "filter by node id")
	cmd.Flags().StringVar(&outcome, "outcome", "", "filter by outcome (success, failure, denied)")
	cmd.Flags().BoolVar(&noPager, "no-pager", false, "do not page output through $PAGER even on a terminal")

	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		c, err := deps.NewClient()
		if err != nil {
			return err
		}
		filter := client.AuditFilter{
			Limit:       limit,
			Action:      action,
			Fingerprint: fingerprint,
			ActorID:     principal,
			Since:       since,
			Until:       until,
			RequestID:   requestID,
			SessionID:   sessionID,
			NodeID:      nodeID,
			Outcome:     outcome,
		}
		entries, correlation, err := c.QueryAudit(cmd.Context(), filter)
		if err != nil {
			return clientError(err, correlation)
		}
		// oldest first
		sort.SliceStable(entries, func(i, j int) bool {
			return entries[i].Time.Before(entries[j].Time)
		})
		if *jsonOut {
			return emitJSON(deps, entries)
		}
		if len(entries) == 0 {
			ui.New(deps.IO.ErrOut, deps.IO.Color).Successln("no audit entries match")
			return nil
		}

		var buf bytes.Buffer
		p := ui.New(&buf, deps.IO.Color)
		renderAuditSummary(p, entries, auditFilterSummary(filter))
		now := time.Now()
		for _, e := range entries {
			renderAuditCard(p, now, e)
		}
		return pageOutput(deps, noPager, buf.String())
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
		renderAuditDetail(deps, *event)
		return nil
	}
	return cmd
}
