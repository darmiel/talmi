package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/darmiel/talmi/internal/core"
	"github.com/darmiel/talmi/pkg/client"
)

var (
	whyToken     string
	whyIssuer    string
	whyManifest  string
	whyReplayID  string
	whyResources []string
	whyJSON      bool
)

var whyCmd = &cobra.Command{
	Use:   "why TOKEN",
	Short: "Explain a policy decision (dry-run, no token is minted)",
	Example: `  talmi why --token "$OIDC" --resource "ghes-corp:acme/x=contents:write"
  talmi why --replay-id d51i...`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		server, err := f.GetRemoteAddr()
		if err != nil {
			return err
		}
		if whyReplayID != "" {
			return whyReplay(cmd, server)
		}

		token := whyToken
		if token == "" && len(args) > 0 {
			token = args[0]
		}
		if token == "" {
			token = os.Getenv("TALMI_TOKEN")
		}
		if token == "" {
			return fmt.Errorf("no token provided (use --token, an argument, or $TALMI_TOKEN)")
		}

		resources, err := gatherResources(whyResources, whyManifest)
		if err != nil {
			return err
		}
		if len(resources) == 0 {
			return fmt.Errorf("no resources provided (use --resource or --manifest)")
		}

		resp, correlation, err := client.New(server).Explain(cmd.Context(), token, client.IssueRequestBody{
			Issuer:    whyIssuer,
			Resources: resources,
		})
		if err != nil {
			return logError(err, correlation, "explain failed")
		}
		if whyJSON {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(resp)
		}

		fmt.Printf("principal: %s %s\n", resp.Principal.ID, faint("(issuer "+resp.Principal.Issuer+")"))
		renderDecision(resp.Decision)
		return nil
	},
}

func whyReplay(cmd *cobra.Command, _ string) error {
	cli, err := f.GetClient()
	if err != nil {
		return err
	}
	entries, correlation, err := cli.QueryAudit(cmd.Context(), client.AuditFilter{
		CorrelationID: whyReplayID,
		Limit:         1,
	})
	if err != nil {
		return logError(err, correlation, "audit lookup failed")
	}
	if len(entries) == 0 {
		return fmt.Errorf("no audit entry with correlation id %q", whyReplayID)
	}

	e := entries[0]
	who := "(unknown)"
	if e.Principal != nil {
		who = e.Principal.ID
	}

	fmt.Printf("lease %s - %s - %s\n", e.ID, e.Action, faint("policy@"+e.Revision))
	fmt.Printf("principal: %s\n", who)
	if e.Decision == nil {
		fmt.Println(faint("  (no decision trace recorded for this entry)"))
		return nil
	}
	renderDecision(*e.Decision)
	return nil
}

func renderDecision(d core.Decision) {
	if d.Authorized {
		fmt.Printf("%s authorized\n", greenCheck)
	} else {
		fmt.Printf("%s denied\n", redCross)
	}
	if len(d.PolicyNames) > 0 {
		fmt.Printf("  matching rules: %s\n", strings.Join(d.PolicyNames, ", "))
	} else {
		fmt.Println("  matching rules: (none)")
	}
	for _, rd := range d.PerRequest {
		mark := greenCheck
		if !rd.Covered {
			mark = redCross
		}
		fmt.Printf("  %s %s=%v", mark, rd.Request.Resource, rd.Request.Actions)
		if !rd.Covered && rd.Reason != "" {
			fmt.Printf("  %s", faint(rd.Reason))
		}
		fmt.Println()
	}
}

func init() {
	rootCmd.AddCommand(whyCmd)

	whyCmd.Flags().StringVar(&whyToken, "token", "", "Upstream OIDC token (or arg / $TALMI_TOKEN)")
	whyCmd.Flags().StringVar(&whyIssuer, "issuer", "", "Explicit issuer name")
	whyCmd.Flags().StringVarP(&whyManifest, "manifest", "R", "", "Resources manifest (yaml)")
	whyCmd.Flags().StringArrayVar(&whyResources, "resource", nil, "Resource realm:body=action[,action] (repeatable)")
	whyCmd.Flags().StringVar(&whyReplayID, "replay-id", "", "Show the recorded decision for a past lease (audit)")
	whyCmd.Flags().BoolVar(&whyJSON, "json", false, "Output raw JSON")
}
