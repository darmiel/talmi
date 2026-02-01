package cmd

import (
	"fmt"
	"sort"
	"time"

	"github.com/fatih/color"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"github.com/darmiel/talmi/pkg/client"
)

var auditInspectCmd = &cobra.Command{
	Use:     "inspect CORRELATION-ID",
	Short:   "Show full details of a specific audit log entry",
	Example: `  talmi audit inspect abc123-def456-ghi789`,
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		correlationID := args[0]
		if correlationID == "" {
			return fmt.Errorf("correlation ID cannot be empty")
		}

		cli, err := f.GetClient()
		if err != nil {
			return err
		}

		log.Debug().Msgf("Retrieving entry with correlation ID '%s'...", correlationID)
		audits, correlation, err := cli.ListAudits(cmd.Context(), client.ListAuditsOpts{
			Limit:         1,
			CorrelationID: correlationID,
		})
		if err != nil {
			return logError(err, correlation, "failed to retrieve audit log entry")
		}
		if len(audits) == 0 {
			log.Warn().Str("correlation_id", correlationID).Msg("no audit log entries found")
			return nil
		}

		entry := audits[0]

		green := color.New(color.FgGreen).SprintFunc()
		red := color.New(color.FgRed).SprintFunc()

		printKV := func(key string, val any) {
			fmt.Printf("  %-26s %v\n", faint(key)+":", val)
		}

		printMap := func(m map[string]any) {
			if len(m) == 0 {
				fmt.Printf("       %s\n", faint("(none)"))
				return
			}
			keys := make([]string, 0, len(m))
			for k := range m {
				keys = append(keys, k)
			}
			sort.Strings(keys)

			for _, k := range keys {
				fmt.Printf("       %-16s %v\n", faint(k)+":", m[k])
			}
		}

		status := green("granted")
		if !entry.Success {
			status = red("denied")
		}

		fmt.Println(bold("\n── Audit Entry ──"))
		printKV("Correlation ID", correlationID)
		printKV("Time", entry.Time.Local().Format(time.RFC1123))
		printKV("Action", entry.Action)
		printKV("Decision", status)

		fmt.Println(bold("\n── Identity ──"))
		if entry.Principal != nil {
			printKV("Subject", entry.Principal.ID)
			printKV("Issuer", entry.Principal.Issuer)
			printKV("Action", entry.Action)
			printKV("Attributes", "")
			printMap(entry.Principal.Attributes)
		} else {
			fmt.Printf("  %s\n", faint("(unknown principal)"))
		}

		fmt.Println(bold("\n── Request & Policy ──"))
		printKV("Action", entry.Action)
		if len(entry.RequestedTargets) > 0 {
			printKV("Req. Targets", "")
			for _, t := range entry.RequestedTargets {
				fmt.Printf("       %s\n", t)
			}
		} else {
			printKV("Req. Targets", faint("(all)"))
		}
		if entry.RequestedIssuer != "" {
			printKV("Req. Issuer", entry.RequestedIssuer)
		} else {
			printKV("Req. Issuer", faint("(auto discover)"))
		}
		if entry.PolicyName != "" {
			printKV("Matched Rule", bold(entry.PolicyName))
		} else {
			printKV("Matched Rule", faint("(none)"))
		}
		if entry.Error != "" {
			printKV("Error Message", red(entry.Error))
		}
		if entry.Stacktrace != "" {
			printKV("Stacktrace", red(entry.Stacktrace))
		}

		fmt.Println(bold("\n── Output ──"))
		if entry.Provider != "" {
			printKV("Provider", entry.Provider)
		} else {
			printKV("Provider", faint("(none)"))
		}
		if entry.TokenFingerprint != "" {
			printKV("Fingerprint", entry.TokenFingerprint)
		} else {
			printKV("Fingerprint", faint("(none)"))
		}
		printKV("Metadata", "")
		printMap(entry.Metadata)
		fmt.Println()

		return nil
	},
}

func init() {
	auditCmd.AddCommand(auditInspectCmd)
}
