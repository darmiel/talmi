package cmd

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/spf13/cobra"

	"github.com/darmiel/talmi/internal/audit"
	"github.com/darmiel/talmi/internal/cli"
	"github.com/darmiel/talmi/internal/cli/ui"
)

func newTokenCmd(deps Deps) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "token",
		Short: "Inspect tokens",
	}
	cmd.AddCommand(
		newTokenInspectCmd(deps),
		newTokenFingerprintCmd(deps),
	)
	return cmd
}

func newTokenInspectCmd(deps Deps) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "inspect [JWT]",
		Short:   "Decode a JWT's claims without verifying it",
		Args:    cobra.ExactArgs(1),
		Example: "  talmi token inspect <JWT>",
	}
	jsonOut := addJSONFlag(cmd)
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		if args[0] == "" {
			return &cli.ExitError{Code: cli.CodeUsage, Message: "token cannot be empty"}
		}
		token, _, err := jwt.NewParser().ParseUnverified(args[0], jwt.MapClaims{})
		if err != nil {
			return &cli.ExitError{Code: cli.CodeUsage, Message: fmt.Sprintf("parsing token: %v", err), Cause: err}
		}
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			return &cli.ExitError{Code: cli.CodeUsage, Message: "invalid token claims"}
		}
		if *jsonOut {
			return emitJSON(deps, claims)
		}
		renderClaims(deps, claims)
		return nil
	}
	return cmd
}

func renderClaims(d Deps, claims jwt.MapClaims) {
	pairs := make([][2]string, 0, len(claims))
	for _, k := range []string{"iss", "sub", "aud"} {
		if v, ok := claims[k]; ok {
			pairs = append(pairs, [2]string{k, fmt.Sprintf("%v", v)})
		}
	}
	if exp, ok := claims["exp"].(float64); ok {
		t := time.Unix(int64(exp), 0)
		pairs = append(pairs, [2]string{
			"exp",
			fmt.Sprintf("%s (in %s)", t.Format(time.RFC3339), time.Until(t).Round(time.Second)),
		})
	}
	rest := make([]string, 0, len(claims))
	for k := range claims {
		switch k {
		case "iss", "sub", "aud", "exp":
		default:
			rest = append(rest, k)
		}
	}
	sort.Strings(rest)
	for _, k := range rest {
		pairs = append(pairs, [2]string{k, fmt.Sprintf("%v", claims[k])})
	}
	ui.WriteKV(d.IO.Out, d.IO.Color, pairs)
}

func newTokenFingerprintCmd(deps Deps) *cobra.Command {
	var (
		providerType string
		raw          bool
	)
	cmd := &cobra.Command{
		Use:     "fingerprint [TOKEN]",
		Aliases: []string{"fp"},
		Short:   "Compute a token fingerprint",
		Args:    cobra.ExactArgs(1),
		Example: "  talmi token fp --type github ghs_...\n" + "" +
			"  echo 'ghs_...' | talmi token fp --type github -",
	}
	cmd.Flags().StringVar(&providerType, "type", "",
		fmt.Sprintf("provider type (one of: %s)", strings.Join(audit.RegisteredFingerprinterTypes(), ", ")))
	cmd.Flags().BoolVarP(&raw, "raw", "r", false, "output only the fingerprint value")
	_ = cmd.MarkFlagRequired("type")

	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		token := args[0]
		if token == "-" {
			data, err := io.ReadAll(deps.IO.In)
			if err != nil {
				return &cli.ExitError{
					Code:    cli.CodeGeneric,
					Message: fmt.Sprintf("reading token from stdin: %v", err),
					Cause:   err,
				}
			}
			token = strings.TrimSpace(string(data))
		}
		if token == "" {
			return &cli.ExitError{Code: cli.CodeUsage, Message: "token cannot be empty"}
		}
		fp := audit.CalculateFingerprint(providerType, token)
		if raw {
			_, _ = fmt.Fprintln(deps.IO.Out, fp)
			return nil
		}
		ui.WriteKV(deps.IO.Out, deps.IO.Color, [][2]string{
			{"Provider Type", providerType},
			{"Fingerprint", fp},
		})
		return nil
	}
	return cmd
}
