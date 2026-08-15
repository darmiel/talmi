package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/goccy/go-yaml"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/spf13/cobra"

	"github.com/darmiel/talmi/internal/cli"
	"github.com/darmiel/talmi/internal/cli/ui"
	"github.com/darmiel/talmi/internal/core"
	"github.com/darmiel/talmi/pkg/client"
)

func newLeaseCmd(deps Deps) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "lease",
		Short: "Issue, revoke and explain leases of downstream tokens",
	}
	cmd.AddCommand(
		newLeaseIssueCmd(deps),
		newLeaseRevokeCmd(deps),
		newLeaseExplainCmd(deps),
	)
	return cmd
}

func newLeaseIssueCmd(deps Deps) *cobra.Command {
	var (
		token     string
		issuer    string
		manifest  string
		out       string
		resources []string
	)
	cmd := &cobra.Command{
		Use:   "issue [TOKEN]",
		Short: "Exchange an OIDC token for downstream resource tokens",
		Long: `Requests a lease of downstream tokens for the given resources. The upstream
OIDC token is taken from --token, the first argument, or $TALMI_TOKEN.
Resources come from repeated --resource flags and/or a --manifest file.`,
		Example: `  talmi lease issue --resource "ghes-corp:acme/svc-a=contents:write" --token "$OIDC"
  talmi lease issue --manifest .talmi/access.yaml --out ./.talmi/out`,
		Args: cobra.MaximumNArgs(1),
	}
	jsonOut := addJSONFlag(cmd)
	cmd.Flags().StringVar(&token, "token", "", "Upstream OIDC token (or use $TALMI_TOKEN / arg)")
	cmd.Flags().StringVar(&issuer, "issuer", "", "Explicit issuer name (skips auto-discovery)")
	cmd.Flags().StringVarP(&manifest, "manifest", "R", "", "Path to a resources manifest (yaml)")
	cmd.Flags().StringVar(&out, "out", "", "Write the full lease (incl. tokens) to <dir>/lease.json")
	cmd.Flags().StringArrayVar(&resources, "resource", nil, "Resource request realm:body=action[,action] (repeatable)")

	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		c, err := deps.NewClient()
		if err != nil {
			return err
		}
		tok := resolveToken(token, args)
		if tok == "" {
			return cli.Fail(cli.CodeUsage, "no token provided").
				Hint("use `--token`, an argument, or `$TALMI_TOKEN`")
		}
		reqs, err := gatherResources(resources, manifest)
		if err != nil {
			return cli.Fail(cli.CodeUsage, fmt.Sprintf("gathering resources: %v", err)).Because(err)
		}
		if len(reqs) == 0 {
			return cli.Fail(cli.CodeUsage, "no resources requested").
				Hint("use `--resource` or `--manifest`")
		}

		sp := ui.NewSpinner(deps.IO.ErrOut, deps.IO.IsTTY && !*jsonOut)
		sp.Start("issuing lease...")
		resp, correlation, err := c.IssueLease(cmd.Context(), tok, client.IssueRequestBody{
			Issuer:    issuer,
			Resources: reqs,
		})
		sp.Stop("" + strings.Repeat(" ", 30)) // TODO: make spinner support clearing line
		if err != nil {
			e := clientError(err, correlation)
			if ee, ok := errors.AsType[*cli.ExitError](e); ok && ee.Code == cli.CodeDenied {
				_ = ee.Hint("see why it was denied: run the same request with `talmi lease explain`")
			}
			return e
		}

		if out != "" {
			if err := writeLease(out, resp); err != nil {
				return err
			}
			ui.New(deps.IO.ErrOut, deps.IO.Color).Successln("wrote lease to %s", filepath.Join(out, "lease.json"))
		}
		if *jsonOut {
			return emitJSON(deps, resp)
		}
		renderLease(deps, resp)
		return nil
	}
	return cmd
}

func newLeaseRevokeCmd(deps Deps) *cobra.Command {
	var (
		secret    string
		fromLease string
		tokens    []string
		yes       bool
	)
	cmd := &cobra.Command{
		Use:   "revoke",
		Short: "Revoke a previously issued lease",
		Long: `Revokes a lease. Provide --from-lease pointing at a lease.json written by
'talmi lease issue --out' (it carries the secret and token values), or pass
--secret and --token artifactID=value flags directly.`,
		Example: `  talmi lease revoke --from-lease ./.talmi/out/lease.json
  talmi lease revoke --secret <secret> --token <artifactID>=<token>`,
		Args: cobra.NoArgs,
	}
	cmd.Flags().StringVar(&fromLease, "from-lease", "", "Path to a lease.json from 'talmi lease issue --out'")
	cmd.Flags().StringVar(&secret, "secret", "", "Revocation secret")
	cmd.Flags().StringArrayVar(&tokens, "token", nil, "artifactID=value (repeatable; for by-value providers)")
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "Skip the confirmation prompt")

	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		c, err := deps.NewClient()
		if err != nil {
			return err
		}
		sec, tokMap, err := gatherRevoke(fromLease, secret, tokens)
		if err != nil {
			return cli.Fail(cli.CodeUsage, fmt.Sprintf("gathering revocation info: %v", err)).Because(err)
		}
		if sec == "" {
			return cli.Fail(cli.CodeUsage, "no revocation secret provided").
				Hint("use `--from-lease` or `--secret`")
		}
		if !yes {
			if !deps.IO.IsTTY {
				return cli.Fail(cli.CodeUsage, "refusing to revoke without confirmation").
					Hint("pass `--yes` to confirm in a non-interactive context")
			}
			confirmed, err := ui.Confirm(deps.IO.In, deps.IO.ErrOut, "revoke this lease?")
			if err != nil {
				return err
			}
			if !confirmed {
				ui.New(deps.IO.ErrOut, deps.IO.Color).Warnln("revocation cancelled")
				return nil
			}
		}

		resp, correlation, err := c.RevokeLease(cmd.Context(), sec, tokMap)
		if err != nil {
			return clientError(err, correlation)
		}
		ui.New(deps.IO.ErrOut, deps.IO.Color).Successln("revoked lease %s (%d artifact(s))", resp.LeaseID, len(resp.Revoked))
		return nil
	}

	return cmd
}

func newLeaseExplainCmd(deps Deps) *cobra.Command {
	var (
		token     string
		issuer    string
		manifest  string
		replayID  string
		resources []string
	)
	cmd := &cobra.Command{
		Use:   "explain [TOKEN]",
		Short: "Explain a policy decision (dry-run, no token is minted)",
		Example: `  talmi lease explain --token "$OIDC" --resource "ghes-corp:acme/x=contents:write"
  talmi lease explain --replay-id d51i...`,
		Args: cobra.MaximumNArgs(1),
	}
	jsonOut := addJSONFlag(cmd)
	cmd.Flags().StringVar(&token, "token", "", "Upstream OIDC token (or arg / $TALMI_TOKEN)")
	cmd.Flags().StringVar(&issuer, "issuer", "", "Explicit issuer name")
	cmd.Flags().StringVarP(&manifest, "manifest", "R", "", "Resources manifest (yaml)")
	cmd.Flags().StringArrayVar(&resources, "resource", nil, "Resource realm:body=action[,action] (repeatable)")
	cmd.Flags().StringVar(&replayID, "replay-id", "", "Show the recorded decision for a past lease (audit)")

	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		c, err := deps.NewClient()
		if err != nil {
			return err
		}
		if replayID != "" {
			return explainReplay(cmd, deps, c, replayID, *jsonOut)
		}

		tok := resolveToken(token, args)
		if tok == "" {
			return cli.Fail(cli.CodeUsage, "no token provided").
				Hint("use `--token`, an argument, or `$TALMI_TOKEN`")
		}
		reqs, err := gatherResources(resources, manifest)
		if err != nil {
			return cli.Fail(cli.CodeUsage, fmt.Sprintf("gathering resources: %v", err)).Because(err)
		}
		if len(reqs) == 0 {
			return cli.Fail(cli.CodeUsage, "no resources requested").
				Hint("use `--resource` or `--manifest`")
		}

		resp, correlation, err := c.Explain(cmd.Context(), tok, client.IssueRequestBody{
			Issuer:    issuer,
			Resources: reqs,
		})
		if err != nil {
			return clientError(err, correlation)
		}
		if *jsonOut {
			return emitJSON(deps, resp)
		}

		p := ui.New(deps.IO.Out, deps.IO.Color)
		p.Printf("principal: %s ", resp.Principal.ID)
		p.Faintln("(issuer %s)", resp.Principal.Issuer)
		renderDecision(deps, resp.Decision)
		renderWouldMint(deps, resp)
		return nil
	}
	return cmd
}

func resolveToken(tokenFlag string, args []string) string {
	if tokenFlag != "" {
		return tokenFlag
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

func gatherRevoke(fromLease, secret string, tokenFlags []string) (string, map[string]string, error) {
	tokens := make(map[string]string)
	if fromLease != "" {
		data, err := os.ReadFile(fromLease)
		if err != nil {
			return "", nil, fmt.Errorf("reading lease file: %w", err)
		}
		var lease client.IssueResponse
		if err := json.Unmarshal(data, &lease); err != nil {
			return "", nil, fmt.Errorf("parsing lease file: %w", err)
		}
		if secret == "" {
			secret = lease.RevocationSecret
		}
		for _, a := range lease.Artifacts {
			if !a.RequiresTokenForRevocation {
				continue
			}
			if a.Token == "" {
				return "", nil, fmt.Errorf(
					"lease file is missing the token for artifact %s (provider %q), which is required to revoke it",
					a.ArtifactID, a.Provider,
				)
			}
			tokens[a.ArtifactID] = a.Token
		}
	}
	for _, tf := range tokenFlags {
		aid, tok, ok := strings.Cut(tf, "=")
		if !ok {
			return "", nil, fmt.Errorf("bad --token %q (want artifactID=value)", tf)
		}
		tokens[aid] = tok
	}
	return secret, tokens, nil
}

func writeLease(fileName string, resp *client.IssueResponse) error {
	data, err := json.MarshalIndent(resp, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(fileName, data, 0o600)
}

func renderLease(deps Deps, resp *client.IssueResponse) {
	ui.New(deps.IO.ErrOut, deps.IO.Color).Successln("lease %s issued (%d artifact(s))", resp.LeaseID, len(resp.Artifacts))

	tw := ui.NewTable(deps.IO.Out)
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
	ui.New(deps.IO.ErrOut, deps.IO.Color).Faintln("token values omitted - use --json or --out to capture them")
}

func explainReplay(cmd *cobra.Command, deps Deps, c TalmiClient, replayID string, jsonOut bool) error {
	entries, correlation, err := c.QueryAudit(cmd.Context(), client.AuditFilter{
		ID:    replayID,
		Limit: 1,
	})
	if err != nil {
		return clientError(err, correlation)
	}
	if len(entries) == 0 {
		return cli.Fail(cli.CodeDenied, fmt.Sprintf("no audit entry with correlation id %q", replayID))
	}

	e := entries[0]
	if jsonOut {
		return emitJSON(deps, e)
	}

	who := "(unknown)"
	if e.Actor != nil {
		who = e.Actor.ID
	}
	p := ui.New(deps.IO.Out, deps.IO.Color)
	p.Printf("lease %s - %s - ", e.ID, string(e.Action))
	p.Faintln("policy@%s", e.Revision)
	p.Printf("principal: %s\n", who)
	if e.Decision == nil {
		p.Faintln("  (no decision trace recorded for this entry)")
		return nil
	}
	renderDecision(deps, *e.Decision)
	return nil
}

func renderDecision(deps Deps, d core.Decision) {
	p := ui.New(deps.IO.Out, deps.IO.Color)
	if d.Authorized {
		rules := "(none)"
		if len(d.PolicyNames) > 0 {
			rules = strings.Join(d.PolicyNames, ", ")
		}
		p.Printf("  %s %s %s\n",
			p.Sprint(ui.StyleSuccess, "\u2713"),
			p.Sprint(ui.StyleSuccess, "authorized"),
			p.Sprint(ui.StyleDim, "· rules: "+rules))
	} else {
		p.Printf("  %s %s\n",
			p.Sprint(ui.StyleError, "\u2717"),
			p.Sprint(ui.StyleError, "denied"))
	}
	for _, rd := range d.PerRequest {
		mark := p.Sprint(ui.StyleSuccess, "\u2713")
		if !rd.Covered {
			mark = p.Sprint(ui.StyleError, "\u2717")
		}
		line := fmt.Sprintf("    %s %s = %v", mark, rd.Request.Resource, rd.Request.Actions)
		if !rd.Covered && rd.Reason != "" {
			p.Printf("%s  %s\n", line, p.Sprint(ui.StyleDim, rd.Reason))
		} else {
			p.Println(line)
		}
	}
}

func renderWouldMint(deps Deps, resp *client.ExplainResponse) {
	if !resp.Decision.Authorized {
		return
	}
	p := ui.New(deps.IO.Out, deps.IO.Color)
	p.Println()
	p.Headingln("Would mint")
	if resp.PlanError != "" {
		p.Printf("  %s %s\n",
			p.Sprint(ui.StyleWarn, "\u26a0"),
			p.Sprint(ui.StyleWarn, resp.PlanError))
		return
	}
	if len(resp.Plan) == 0 {
		p.Faintln("  (nothing to mint)")
		return
	}
	for _, mp := range resp.Plan {
		covers := make([]string, 0, len(mp.Covers))
		for _, cr := range mp.Covers {
			acts := make([]string, len(cr.Actions))
			for i, a := range cr.Actions {
				acts[i] = string(a)
			}
			covers = append(covers, string(cr.Resource)+"="+strings.Join(acts, ","))
		}
		p.Printf("  %s %s  %s\n",
			p.Sprint(ui.StyleDim, "\u2022"),
			p.Sprint(ui.StyleBold, mp.Provider),
			p.Sprint(ui.StyleDim, strings.Join(covers, "  ")))
	}
}
