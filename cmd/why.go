package cmd

import (
	"fmt"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/darmiel/talmi/internal/core"
	"github.com/darmiel/talmi/pkg/client"
)

var (
	whyToken      string
	whyProvider   string
	whyIssuer     string
	whyRuleFilter string
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
		cli, err := getClient()
		if err != nil {
			return err
		}

		trace, err := cli.ExplainTrace(cmd.Context(), whyToken, client.ExplainTraceOptions{
			RequestedIssuer:   whyIssuer,
			RequestedProvider: whyProvider,
		})
		if err != nil {
			return err
		}

		printTrace(trace)
		return nil
	},
}

func printTrace(trace *core.EvaluationTrace) {
	bold := color.New(color.Bold).SprintFunc()
	green := color.New(color.FgGreen).SprintFunc()
	red := color.New(color.FgRed).SprintFunc()
	yellow := color.New(color.FgYellow).SprintFunc()
	italic := color.New(color.Italic).SprintFunc()

	fmt.Printf("\n%s for Principal: %s (Issuer: %s)\n",
		bold("Evaluation Trace"),
		bold(trace.Principal.ID),
		trace.Principal.Issuer)

	fmt.Println("---------------------------------------------------")

	for _, res := range trace.RuleResults {
		if whyRuleFilter != "" && res.RuleName != whyRuleFilter {
			continue
		}

		icon := red("✖")
		if res.Matched {
			icon = green("✔")
		}

		fmt.Printf("%s Rule: %s\n", icon, bold(res.RuleName))
		if res.Description != "" {
			fmt.Printf("  %s\n", italic(res.Description))
		}

		for _, cond := range res.ConditionResults {
			condIcon := red("✖")
			if cond.Passed {
				condIcon = green("✔")
			}

			fmt.Printf("    %s %s\n", condIcon, cond.Expression)
			if !cond.Passed {
				fmt.Printf("        Reason: %s\n", yellow(cond.Reason))
			}
		}

		fmt.Println()
	}

	fmt.Println("---------------------------------------------------")
	if trace.FinalDecision {
		fmt.Printf("Final Decision: %s via rule '%s'\n", green("allowed"), trace.GrantedRule)
	} else {
		fmt.Printf("Final Decision: %s\n", red("denied"))
	}
	fmt.Println()
}

func init() {
	rootCmd.AddCommand(whyCmd)

	whyCmd.Flags().StringVarP(&whyToken, "token", "t", "", "Token to explain")
	whyCmd.Flags().StringVarP(&whyRuleFilter, "rule", "r", "", "Filter output to specific rule name (optional)")
	whyCmd.Flags().StringVar(&whyProvider, "provider", "", "Simulate requesting this provider (optional)")
	whyCmd.Flags().StringVar(&whyIssuer, "issuer", "", "Simulate coming from this issuer (optional)")

	_ = whyCmd.MarkFlagRequired("token")
}
