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

// whyCmd represents the why command
var whyCmd = &cobra.Command{
	Use:   "why",
	Short: "Explain why a token matches (or does not match) policies",
	Long:  "", // TODO
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

	whyCmd.Flags().StringVar(&whyToken, "token", "", "Token to explain")
	whyCmd.Flags().StringVar(&whyProvider, "provider", "", "Requested provider")
	whyCmd.Flags().StringVar(&whyIssuer, "issuer", "", "Requested issuer")
	whyCmd.Flags().StringVar(&whyRuleFilter, "rule", "", "Focus on a specific rule")

	_ = whyCmd.MarkFlagRequired("token")
}
