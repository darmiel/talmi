package cmd

import (
	"errors"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/darmiel/talmi/internal/cli"
)

func rootWithChildren() *cobra.Command {
	root := &cobra.Command{Use: "talmi"}
	root.AddCommand(
		&cobra.Command{Use: "lease"},
		&cobra.Command{Use: "audit"},
		&cobra.Command{Use: "session"},
	)
	return root
}

func TestDidYouMeanCommand(t *testing.T) {
	t.Parallel()
	hints := didYouMean(`unknown command "lesae" for "talmi"`, rootWithChildren())
	require.NotEmpty(t, hints)
	assert.Contains(t, hints[0], "lease")
}

func TestDidYouMeanFlag(t *testing.T) {
	t.Parallel()
	cmd := &cobra.Command{Use: "issue"}
	cmd.Flags().String("resource", "", "")
	hints := didYouMean(`unknown flag: --resrouce`, cmd)
	require.NotEmpty(t, hints)
	assert.Contains(t, hints[0], "--resource")
}

func TestDidYouMeanNoMatchReturnsNil(t *testing.T) {
	t.Parallel()
	assert.Empty(t, didYouMean("some unrelated error", rootWithChildren()))
}

func TestEnrichAddsUsageHelp(t *testing.T) {
	t.Parallel()
	cmd := &cobra.Command{Use: "issue"}
	root := &cobra.Command{Use: "talmi"}
	root.AddCommand(cmd)

	got := enrich(cli.Fail(cli.CodeUsage, "bad input"), nil, cmd)
	var ee *cli.ExitError
	require.ErrorAs(t, got, &ee)

	joined := ""
	for _, h := range ee.Hints {
		joined += h + "\n"
	}
	assert.Contains(t, joined, "--help")
}

func TestEnrichLeavesNonExitErrorAlone(t *testing.T) {
	t.Parallel()
	plain := errors.New("plain")
	assert.Equal(t, plain, enrich(plain, nil, &cobra.Command{Use: "x"}))
}
