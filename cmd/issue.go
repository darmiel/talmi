package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/goccy/go-yaml"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/spf13/cobra"

	"github.com/darmiel/talmi/pkg/client"
)

var (
	issueTokenFlag string
	issueIssuer    string
	issueManifest  string
	issueOut       string
	issueResources []string
	issueJSON      bool
)

var issueCmd = &cobra.Command{
	Use:   "issue TOKEN",
	Short: "Exchange an OIDC token for downstream resource tokens",
	Long: `Requests a lease of downstream tokens for the given resources. The upstream
OIDC token is taken from --token, the first argument, or $TALMI_OIDC_TOKEN.
Resources come from repeated --resource flags and/or a --manifest file.`,
	Example: `  talmi issue --resource "ghes-corp:acme/svc-a=contents:write" --token "$OIDC"
  talmi issue --manifest .talmi/access.yaml --out ./.talmi/out`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		server, err := f.GetRemoteAddr()
		if err != nil {
			return err
		}
		token := resolveToken(args)
		if token == "" {
			return fmt.Errorf("no token provided, use --token or $TALMI_TOKEN")
		}
		resources, err := gatherResources(issueResources, issueManifest)
		if err != nil {
			return err
		}
		if len(resources) == 0 {
			return fmt.Errorf("no resources requested (use --resource or --manifest)")
		}

		resp, correlation, err := client.New(server).IssueLease(cmd.Context(), token, client.IssueRequestBody{
			Issuer:    issueIssuer,
			Resources: resources,
		})
		if err != nil {
			return logError(err, correlation, "issuance failed")
		}

		if issueOut != "" {
			if err := writeLease(issueOut, resp); err != nil {
				return err
			}
			logSuccess("wrote lease to %s", filepath.Join(issueOut, "lease.json"))
		}
		if issueJSON {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(resp)
		}

		renderLease(resp)
		return nil
	},
}

func resolveToken(args []string) string {
	if issueTokenFlag != "" {
		return issueTokenFlag
	}
	if len(args) > 0 && args[0] != "" {
		return args[0]
	}
	return os.Getenv("TALMI_TOKEN")
}

func gatherResources(flags []string, manifestPath string) ([]client.ResourceRequest, error) {
	out := make([]client.ResourceRequest, 0, len(flags))
	for _, f := range flags {
		res, actions, ok := strings.Cut(f, "=")
		if !ok || res == "" || actions == "" {
			return nil, fmt.Errorf("bad --resource %q (want realm:body=action[,action])", f)
		}
		out = append(out, client.ResourceRequest{
			Resource: res,
			Actions:  strings.Split(actions, ","),
		})
	}
	if manifestPath != "" {
		data, err := os.ReadFile(manifestPath)
		if err != nil {
			return nil, fmt.Errorf("reading manifest: %w", err)
		}
		var m struct {
			Resource []struct {
				Resource string   `yaml:"resource"`
				Actions  []string `yaml:"actions"`
			} `yaml:"resources"`
		}
		if err := yaml.Unmarshal(data, &m); err != nil {
			return nil, fmt.Errorf("parsing manifest: %w", err)
		}
		for _, r := range m.Resource {
			out = append(out, client.ResourceRequest{
				Resource: r.Resource,
				Actions:  r.Actions,
			})
		}
	}
	return out, nil
}

func writeLease(dir string, resp *client.IssueResponse) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("creating out dir: %w", err)
	}
	data, err := json.MarshalIndent(resp, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "lease.json"), data, 0o600)
}

func renderLease(resp *client.IssueResponse) {
	logSuccess("lease %s issued (%d artifact(s))", resp.LeaseID, len(resp.Artifacts))

	tw := table.NewWriter()
	applyTableFormat(tw)
	tw.SetOutputMirror(os.Stdout)
	tw.AppendHeader(table.Row{"Artifact", "Provider", "Realm", "Covers", "Expires", "RevToken?"})
	for _, a := range resp.Artifacts {
		revTok := "no"
		if a.RequiresTokenForRevocation {
			revTok = "yes"
		}
		tw.AppendRow(table.Row{
			a.ArtifactID, a.Provider, a.Realm, strings.Join(a.Covers, ","),
			a.ExpiresAt.Local().Format(time.RFC3339), revTok,
		})
	}
	tw.Render()
	fmt.Println(faint("  token values omitted - use --json or --out to capture them"))
}

func init() {
	rootCmd.AddCommand(issueCmd)
	issueCmd.Flags().StringVar(&issueTokenFlag, "token", "", "Upstream OIDC token (or use $TALMI_OIDC_TOKEN / arg)")
	issueCmd.Flags().StringVar(&issueIssuer, "issuer", "", "Explicit issuer name (skips auto-discovery)")
	issueCmd.Flags().StringVarP(&issueManifest, "manifest", "R", "", "Path to a resources manifest (yaml)")
	issueCmd.Flags().StringVar(&issueOut, "out", "", "Write the full lease (incl. tokens) to <dir>/lease.json")
	issueCmd.Flags().StringArrayVar(&issueResources, "resource", nil, "Resource request realm:body=action[,action] (repeatable)")
	issueCmd.Flags().BoolVar(&issueJSON, "json", false, "Print the full lease as JSON")
}
