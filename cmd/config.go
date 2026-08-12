package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/darmiel/talmi/internal/backend"
	"github.com/darmiel/talmi/internal/cli"
	"github.com/darmiel/talmi/internal/cli/ui"
	"github.com/darmiel/talmi/internal/config"
	"github.com/darmiel/talmi/internal/configvet"
	"github.com/darmiel/talmi/internal/core"
	"github.com/darmiel/talmi/internal/source"
)

func newConfigCmd(deps Deps) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Interact with the configuration",
		Long:  `Utilities for validating and viewing the Talmi configuration`,
	}
	cmd.AddCommand(
		newConfigVetCmd(deps),
		newConfigSchemaCmd(deps),
	)
	return cmd
}

func newConfigVetCmd(deps Deps) *cobra.Command {
	var (
		online bool
		strict bool
		local  bool
		ref    string
	)
	cmd := &cobra.Command{
		Use:   "vet [config.yaml]",
		Short: "Validate a Talmi configuration",
		Args:  cobra.MaximumNArgs(1),
	}
	jsonOut := addJSONFlag(cmd)
	cmd.Flags().BoolVar(&online, "online", false, "perform network-based checks (may be slow)")
	cmd.Flags().BoolVar(&strict, "strict", false, "treat warnings as errors")
	cmd.Flags().BoolVar(&local, "local", false, "force local config source (ignore remote)")
	cmd.Flags().StringVar(&ref, "ref", "", "override git ref for remote config source")

	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		path := "talmi.yaml"
		if len(args) == 1 {
			path = args[0]
		}

		cfg, err := config.Load(path)
		if err != nil {
			return cli.Fail(cli.CodeConfig, fmt.Sprintf("could not load config: %v", err)).Because(err)
		}
		if err := validateVetSourceFlags(local, ref); err != nil {
			return cli.Fail(cli.CodeUsage, err.Error()).Because(err)
		}

		src, err := source.Resolve(cfg, filepath.Dir(path), source.Options{
			ForceLocal: local,
			Ref:        ref,
		})
		if err != nil {
			return cli.Fail(cli.CodeConfig, fmt.Sprintf("could not resolve config source: %v", err)).Because(err)
		}

		sourced, revision, err := src.Load(cmd.Context())
		if err != nil {
			return cli.Fail(cli.CodeConfig, fmt.Sprintf("could not load config source: %v", err)).Because(err)
		}
		if revision != "" && revision != "local" && cfg.ConfigSource != nil && cfg.ConfigSource.GitHub != nil {
			ui.New(deps.IO.ErrOut, deps.IO.Color).Successln("vetting %s/%s@%s",
				cfg.ConfigSource.GitHub.Owner, cfg.ConfigSource.GitHub.Repo, revision)
		}

		staticIn := configvet.StaticInput{
			Config:  cfg,
			Sourced: sourced,
			Realms:  configvet.RealmRegistry(sourced.Realms),
		}

		var report configvet.Report
		if online {
			providers, buildFindings := buildProvidersForVet(sourced)
			report = configvet.Live(cmd.Context(), configvet.LiveInput{
				Static:    staticIn,
				Providers: providers,
			})
			report.Findings = append(buildFindings, report.Findings...)
		} else {
			report = configvet.Static(staticIn)
		}

		if *jsonOut {
			if err := configvet.RenderJSON(deps.IO.Out, report); err != nil {
				return err
			}
		} else {
			configvet.RenderText(deps.IO.Out, report, deps.IO.Color)
		}

		if report.HasErrors() || (strict && len(report.Warnings()) > 0) {
			return cli.Fail(cli.CodeConfig, "configuration is invalid")
		}
		return nil
	}
	return cmd
}

func newConfigSchemaCmd(deps Deps) *cobra.Command {
	var out string
	cmd := &cobra.Command{
		Use:   "schema [target]",
		Short: "Generate JSON Schema for Talmi configuration",
		Args:  cobra.MaximumNArgs(1),
	}
	cmd.Flags().StringVarP(&out, "out", "o", "", "output file for schema (default stdout)")
	cmd.RunE = func(_ *cobra.Command, args []string) error {
		target := "config"
		if len(args) == 1 {
			target = args[0]
		}
		data, err := config.GenerateSchema(target)
		if err != nil {
			return cli.Fail(cli.CodeUsage, fmt.Sprintf("could not generate schema: %v", err)).Because(err)
		}
		data = append(data, '\n')
		if out == "" || out == "-" {
			_, err = deps.IO.Out.Write(data)
			return err
		}
		if err := os.WriteFile(out, data, 0o600); err != nil {
			return fmt.Errorf("writing schema: %w", err)
		}
		ui.New(deps.IO.ErrOut, deps.IO.Color).Successln("wrote %s schema to %s", target, out)
		return nil
	}
	return cmd
}

func buildProvidersForVet(sourced *config.SourcedConfig) ([]core.ResourceProvider, []configvet.Finding) {
	var findings []configvet.Finding
	specs, err := config.ExpandProviders(sourced.Realms)
	if err != nil {
		return nil, []configvet.Finding{
			{
				Severity: configvet.SeverityError,
				Code:     "CFG-PROVIDER-BUILD",
				Section:  "realms",
				Message:  err.Error(),
			},
		}
	}
	provs := make([]core.ResourceProvider, 0, len(specs))
	for _, spec := range specs {
		b, ok := backend.Lookup(spec.Type)
		if !ok {
			continue // already reported by static pass
		}
		p, err := b.Build(backend.BuildInput{
			Spec: spec,
		})
		if err != nil {
			findings = append(findings, configvet.Finding{
				Severity: configvet.SeverityError,
				Code:     "CFG-PROVIDER-BUILD",
				Section:  "realms",
				Location: "realms/instances[" + spec.Name + "]",
				Message:  fmt.Sprintf("could not build provider %q: %v", spec.Name, err),
			})
			continue
		}
		provs = append(provs, p)
	}

	return provs, findings
}

func validateVetSourceFlags(local bool, ref string) error {
	if local && ref != "" {
		return fmt.Errorf("--local and --ref cannot be used together")
	}
	return nil
}
