package cmd

import (
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/darmiel/talmi/internal/buildinfo"
	"github.com/darmiel/talmi/internal/cli"
	"github.com/darmiel/talmi/internal/cliconfig"
	"github.com/darmiel/talmi/pkg/client"
)

func buildDeps(io cli.IOStreams) Deps {
	return Deps{
		IO:         io,
		Build:      buildinfo.GetBuildInfo(),
		NewClient:  newTalmiClient,
		RemoteAddr: remoteAddr,
	}
}

func registerCommands(root *cobra.Command, deps Deps) {
	root.AddCommand(
		newVersionCmd(deps),
		newServerCmd(deps),
		newTokenCmd(deps),
		newSessionCmd(deps),
		newAuditCmd(deps),
		newTasksCmd(deps),
		newLeaseCmd(deps),
		newConfigCmd(deps),
	)
}

func Execute() {
	io := cli.SystemStreams()
	deps := buildDeps(io)

	rootCmd.SetOut(io.Out)
	rootCmd.SetErr(io.ErrOut)

	registerCommands(rootCmd, deps)
	disableCobraSuggestions(rootCmd)

	cmd, execErr := rootCmd.ExecuteC()
	os.Exit(cli.Handle(io, enrich(classify(execErr, ""), execErr, cmd)))
}

func disableCobraSuggestions(cmd *cobra.Command) {
	cmd.DisableSuggestions = true
	for _, c := range cmd.Commands() {
		disableCobraSuggestions(c)
	}
}

// remoteAddr resolves the target server from --server, $TALMI_ADDR or the CLI config file.
func remoteAddr() (string, error) {
	server := viper.GetString(TalmiAddrKey)
	if server == "" {
		return "", errServerNotConfigured()
	}
	return server, nil
}

// newTalmiClient builds an authenticated client for the configured server.
func newTalmiClient() (TalmiClient, error) {
	server, err := remoteAddr()
	if err != nil {
		return nil, err
	}
	var token string
	if cfg, err := cliconfig.Load(); err == nil {
		if cred, err := cfg.GetCredential(server); err == nil {
			// token prio 1: from saved credential
			token = cred.Token
		}
	}
	if envToken := os.Getenv("TALMI_TOKEN"); envToken != "" {
		// token prio 2: from env var
		token = envToken
	}
	return client.New(server, client.WithAuthToken(token)), nil
}

func errServerNotConfigured() error {
	return cli.Fail(cli.CodeUsage, "server address not configured").
		Hint("set `--server` or the `TALMI_ADDR` environment variable")
}
