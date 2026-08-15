package cmd

import (
	"github.com/spf13/cobra"

	"github.com/darmiel/talmi/internal/cli"
	"github.com/darmiel/talmi/internal/cli/ui"
)

func newProviderCmd(deps Deps) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "provider",
		Aliases: []string{"providers"},
		Short:   "Inspect providers and preview how requests resolve (requires admin session)",
	}
	cmd.AddCommand(
		newProviderListCmd(deps),
		newProviderResolveCmd(deps),
	)
	return cmd
}

func newProviderListCmd(deps Deps) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List provider instances and their live effective capability",
		Args:    cobra.NoArgs,
	}
	jsonOut := addJSONFlag(cmd)
	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		c, err := deps.NewClient()
		if err != nil {
			return err
		}
		infos, correlation, err := c.Providers(cmd.Context())
		if err != nil {
			return clientError(err, correlation)
		}
		if *jsonOut {
			return emitJSON(deps, infos)
		}
		if len(infos) == 0 {
			ui.New(deps.IO.ErrOut, deps.IO.Color).Successln("no providers configured")
			return nil
		}
		renderProviderList(deps, infos)
		return nil
	}
	return cmd
}

func newProviderResolveCmd(deps Deps) *cobra.Command {
	var verbose bool
	cmd := &cobra.Command{
		Use:   "resolve [RESOURCE=ACTIONS...]",
		Short: "Preview which resolver would serve each request (no token is minted)",
		Example: `  talmi provider resolve "ghes-corp:acme/x=contents:read"
  talmi provider resolve --verbose "ghes-corp:acme/x=contents:write"`,
		Args: cobra.MinimumNArgs(1),
	}
	jsonOut := addJSONFlag(cmd)
	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Show the candidate provider breakdown")
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		c, err := deps.NewClient()
		if err != nil {
			return err
		}
		reqs, err := gatherResources(args, "")
		if err != nil {
			return cli.Fail(cli.CodeUsage, err.Error())
		}
		res, correlation, err := c.Resolve(cmd.Context(), reqs)
		if err != nil {
			return clientError(err, correlation)
		}
		if *jsonOut {
			return emitJSON(deps, res)
		}
		renderProviderResolve(deps, res, verbose)
		return nil
	}
	return cmd
}
