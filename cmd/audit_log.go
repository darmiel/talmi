package cmd

import (
	"fmt"
	"os"
	"time"

	"github.com/fatih/color"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var (
	auditLogLimit   uint
	auditLogDisplay string // either table or text
)

var auditLogCmd = &cobra.Command{
	Use:     "log",
	Short:   "Retrieve and display audit log entries",
	Long:    `Fetches the most recent decision logs from the server, including allowed and denied requests`,
	Example: `  talmi audit log --limit 50`,
	RunE: func(cmd *cobra.Command, args []string) error {
		cli, err := getClient()
		if err != nil {
			return err
		}

		var isTable bool
		switch auditLogDisplay {
		case "table":
			isTable = true
		case "text":
			isTable = false
		default:
			return fmt.Errorf("invalid output format: %s", auditLogDisplay)
		}

		log.Info().Msg("Fetching audit log...")
		audits, err := cli.ListAudits(cmd.Context(), auditLogLimit)
		if err != nil {
			return err
		}
		log.Info().Msgf("Retrieved %d audit entries", len(audits))

		t := table.NewWriter()
		t.SetOutputMirror(os.Stdout)
		t.AppendHeader(table.Row{
			"Time", "Action", "Principal", "Granted", "Provider", "Error",
		})

		bold := color.New(color.Bold).SprintFunc()
		green := color.New(color.FgGreen).SprintFunc()
		red := color.New(color.FgRed).SprintFunc()
		faint := color.New(color.Faint).SprintFunc()

		for _, e := range audits {
			subRaw := "(unknown)"
			sub := faint(subRaw)
			if e.Principal != nil {
				subRaw = truncate(e.Principal.ID, 64)
				sub = bold(subRaw)
			}

			var granted string
			if e.Granted {
				granted = green("✔") + " " + e.PolicyName

				if !isTable {
					fmt.Printf("%s: %s %s %s via '%s'\n",
						faint(e.Time.Format(time.RFC3339)),
						bold(subRaw),
						green("✔ "+e.Action),
						faint(e.Provider),
						bold(e.PolicyName))
				}
			} else {
				granted = red("✖")
				sub = red(subRaw) // make it red!

				if !isTable {
					fmt.Printf("%s: %s %s: %s\n",
						faint(e.Time.Format(time.RFC3339)),
						bold(subRaw),
						red("✖ "+e.Action),
						e.Error)
				}
			}

			t.AppendRow(table.Row{
				e.Time.Format(time.RFC3339),
				e.Action,
				sub,
				granted,
				e.Provider,
				red(e.Error),
			})
		}

		if isTable {
			s := table.StyleRounded
			s.Format.Header = text.FormatDefault
			t.SetStyle(s)
			t.Render()
		}
		return nil
	},
}

func init() {
	auditCmd.AddCommand(auditLogCmd)

	auditLogCmd.Flags().UintVarP(&auditLogLimit, "limit", "n", 25, "Number of entries")
	auditLogCmd.Flags().StringVarP(&auditLogDisplay, "output", "o", "table", "Output format: table or text")
}
