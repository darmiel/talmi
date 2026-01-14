package cmd

import (
	"fmt"
	"strings"

	"github.com/fatih/color"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"github.com/darmiel/talmi/internal/config"
	"github.com/darmiel/talmi/internal/core"
	"github.com/darmiel/talmi/internal/engine"
	"github.com/darmiel/talmi/internal/issuers"
	"github.com/darmiel/talmi/pkg/client"
)

var (
	whyToken        string
	whyProvider     string
	whyIssuer       string
	whyFilterIssuer bool
	whyRuleFilter   string
	whyTargetFile   string
	whyReplayID     string
)

var whyCmd = &cobra.Command{
	Use:   "why",
	Short: "Explain why a token matches (or does not match) policies",
	Long: `Simulates a request against the server and returns a detailed trace of the policy evaluation.
	Useful for debugging why a specific token is being denied or matching the wrong rule.

Note: This command requires a Talmi server to be running and reachable.
Also note that you need to be authenticated as admin to use this command.`,
	Example: `  # Why is my token denied? Which rules is it matching?
  talmi why --token <token>
  
  # Why is it not matching the 'admin' rule?
  talmi why --token <token> --rule admin`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if whyTargetFile != "" {
			// if -f is passed, handle it locally
			log.Debug().Msg("Running 'why' command in local mode")
			return whyTokenLocally(cmd, args)
		}
		// otherwise, expect to issue from remote server
		log.Debug().Msg("Running 'why' command in remote mode")
		return whyTokenRemote(cmd, args)
	},
}

func init() {
	rootCmd.AddCommand(whyCmd)

	whyCmd.Flags().StringVarP(&whyTargetFile, "config", "f", "", "Run locally using this config file")
	whyCmd.Flags().StringVarP(&whyToken, "token", "t", "", "Token to explain")
	whyCmd.Flags().StringVarP(&whyRuleFilter, "rule", "r", "", "Filter output to specific rule name (optional)")
	whyCmd.Flags().StringVar(&whyProvider, "provider", "", "Simulate requesting this provider (optional)")
	whyCmd.Flags().StringVar(&whyIssuer, "issuer", "", "Simulate coming from this issuer (optional)")
	whyCmd.Flags().StringVar(&whyReplayID, "replay-id", "", "Replay a specific audit log entry by its ID (optional)")
	whyCmd.Flags().BoolVar(&whyFilterIssuer, "filter-issuer", false, "Only show entries where the issuer matched (optional)")

	whyCmd.MarkFlagsOneRequired("token", "replay-id")        // either token or replay-id is required
	whyCmd.MarkFlagsMutuallyExclusive("config", "replay-id") // cannot use replay-id in local mode
}

func whyTokenRemote(cmd *cobra.Command, _ []string) error {
	cli, err := f.GetClient()
	if err != nil {
		return err
	}

	trace, err := cli.ExplainTrace(cmd.Context(), whyToken, client.ExplainTraceOptions{
		RequestedIssuer:   whyIssuer,
		RequestedProvider: whyProvider,
		ReplayID:          whyReplayID,
	})
	if err != nil {
		return err
	}

	printTrace(trace)
	return nil
}

func whyTokenLocally(cmd *cobra.Command, _ []string) error {
	cfg, err := config.Load(whyTargetFile)
	if err != nil {
		return err
	}

	// initialize registries
	issuerRegistry, err := issuers.BuildRegistry(cmd.Context(), cfg.Issuers)
	if err != nil {
		return err
	}

	eng := engine.New(cfg.Rules)
	var iss core.Issuer

	// if an issuer was passed, use it
	if whyIssuer != "" {
		issuerByName, ok := issuerRegistry.Get(whyIssuer)
		if !ok {
			return fmt.Errorf("issuer '%s' not found in config", whyIssuer)
		}
		iss = issuerByName
	} else {
		// otherwise use the discovery service to find the corresponding issuer
		issuerByURL, err := issuerRegistry.IdentifyIssuer(whyToken)
		if err != nil {
			return fmt.Errorf("cannot determine issue from URL: %w", err)
		}
		iss = issuerByURL
	}
	log.Debug().Msgf("Using issuer: '%s'", iss.Name())

	// validate the (OIDC) token and return principal
	log.Info().Msgf("Verifying token with issuer '%s'...", whyIssuer)
	principal, err := iss.Verify(cmd.Context(), whyToken)
	if err != nil {
		return fmt.Errorf("verification failed: %w", err)
	}
	log.Info().Msgf("Identity verified. Principals attributes: %v", principal.Attributes)

	trace := eng.Trace(principal, whyProvider)
	printTrace(&trace)
	return nil
}

func printTrace(trace *core.EvaluationTrace) {
	bold := color.New(color.Bold).SprintFunc()
	faint := color.New(color.Faint).SprintFunc()

	green := color.New(color.FgGreen).SprintFunc()
	red := color.New(color.FgRed).SprintFunc()
	yellow := color.New(color.FgYellow).SprintFunc()
	cyan := color.New(color.FgCyan).SprintFunc()

	fmt.Printf("\n%s for principal %s and issuer: %s\n",
		bold("Evaluation Trace"),
		bold(trace.Principal.ID),
		bold(trace.Principal.Issuer))

	fmt.Println(faint("---------------------------------------------------"))

	for _, res := range trace.RuleResults {
		if whyRuleFilter != "" && res.RuleName != whyRuleFilter {
			continue
		}

		// this is a hacky way to check if the issuer matched. we can fix this later :)
		if whyFilterIssuer {
			issuerMatched := false
			for _, cond := range res.ConditionResults {
				if strings.HasPrefix(cond.Expression, "issuer equals '") && cond.Matched {
					issuerMatched = true
					break
				}
			}
			if !issuerMatched {
				continue
			}
		}

		icon := red("✖")
		if res.Matched {
			icon = green("✔")
		}

		fmt.Printf("%s Rule: %s\n", icon, bold(res.RuleName))
		if res.Description != "" {
			fmt.Printf("  %s\n", faint(res.Description))
		}

		for _, cond := range res.ConditionResults {
			// calculate depth based on leading spaces
			trimmed := strings.TrimLeft(cond.Expression, " ")
			indentLen := len(cond.Expression) - len(trimmed)
			indent := strings.Repeat(" ", indentLen)

			// detect if this is a label
			isLogicGate := strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]")

			condIcon := red("✖")
			if cond.Matched {
				condIcon = green("✔")
			}

			if isLogicGate {
				fmt.Printf("    %s%s %s\n", indent, condIcon, cyan(trimmed))
			} else {
				fmt.Printf("    %s%s %s\n", indent, condIcon, trimmed)
			}

			if cond.Reason != "" {
				reasonIndent := indent + "       "
				reason := cond.Reason
				if cond.Matched {
					reason = faint(reason)
				} else {
					reason = yellow(reason)
				}
				fmt.Printf("%s↳ %s\n", reasonIndent, reason)
			}
		}

		fmt.Println()
	}

	fmt.Println("---------------------------------------------------")
	if trace.FinalDecision {
		fmt.Printf("Decision: %s via rule '%s'\n", bold(green("allowed")), bold(trace.GrantedRule))
	} else {
		fmt.Printf("Decision: %s\n", bold(red("denied")))
	}
	fmt.Println()
}
