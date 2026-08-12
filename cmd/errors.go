package cmd

import (
	"errors"
	"fmt"
	"regexp"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/darmiel/talmi/internal/cli"
	"github.com/darmiel/talmi/internal/configvet"
)

var (
	reUnknownCommand = regexp.MustCompile(`unknown command "([^"]+)"`)
	reUnknownFlag    = regexp.MustCompile(`unknown (?:shorthand )?flag: -+(\S+)`)
)

func enrich(err, orig error, cmd *cobra.Command) error {
	var ee *cli.ExitError
	ok := errors.As(err, &ee)
	if !ok || ee == nil {
		return err
	}
	if orig != nil && cmd != nil {
		_ = ee.Hint(didYouMean(orig.Error(), cmd)...)
	}
	if ee.Code == cli.CodeUsage && cmd != nil {
		_ = ee.Hint(fmt.Sprintf("run `%s --help` for usage", cmd.CommandPath()))
	}
	return ee
}

func didYouMean(msg string, cmd *cobra.Command) []string {
	if m := reUnknownCommand.FindStringSubmatch(msg); m != nil {
		var names []string
		for _, c := range cmd.Commands() {
			if !c.Hidden {
				names = append(names, c.Name())
			}
		}
		return didYouMeanHints(m[1], names, "")
	}
	if m := reUnknownFlag.FindStringSubmatch(msg); m != nil {
		var names []string
		cmd.Flags().VisitAll(func(flag *pflag.Flag) {
			names = append(names, flag.Name)
		})
		return didYouMeanHints(m[1], names, "--")
	}
	return nil
}

func didYouMeanHints(target string, candidates []string, prefix string) []string {
	matches := configvet.Suggest(target, candidates)
	if len(matches) == 0 {
		return nil
	}
	return []string{fmt.Sprintf("did you mean `%s%s`?", prefix, matches[0])}
}
