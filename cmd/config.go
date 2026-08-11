package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/darmiel/talmi/internal/backend"
	"github.com/darmiel/talmi/internal/config"
	"github.com/darmiel/talmi/internal/configvet"
	"github.com/darmiel/talmi/internal/core"
	"github.com/darmiel/talmi/internal/source"
)

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Interact with the configuration",
	Long:  `Utilities for validating and viewing the Talmi configuration`,
}

var (
	vetOnline bool
	vetStrict bool
	vetFormat string
	vetLocal  bool
	vetRef    string
)

var configVetCmd = &cobra.Command{
	Use:   "vet [config.yaml]",
	Short: "Validate a Talmi configuration",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		path := "talmi.yaml"
		if len(args) == 1 {
			path = args[0]
		}

		cfg, err := config.Load(path)
		if err != nil {
			return logError(err, "", "could not load config")
		}
		if err := validateVetSourceFlags(vetLocal, vetRef); err != nil {
			return logError(err, "", "invalid source flags")
		}

		src, err := source.Resolve(cfg, filepath.Dir(path), source.Options{
			ForceLocal: vetLocal,
			Ref:        vetRef,
		})
		if err != nil {
			return logError(err, "", "could not resolve config source")
		}

		sourced, revision, err := src.Load(cmd.Context())
		if err != nil {
			return logError(err, "", "could not load sourced config tree")
		}
		if revision != "" && revision != "local" && cfg.ConfigSource != nil && cfg.ConfigSource.GitHub != nil {
			logSuccess("vetting %s/%s@%s", cfg.ConfigSource.GitHub.Owner, cfg.ConfigSource.GitHub.Repo, revision)
		}

		staticIn := configvet.StaticInput{
			Config:  cfg,
			Sourced: sourced,
			Realms:  configvet.RealmRegistry(sourced.Realms),
		}

		var report configvet.Report
		if vetOnline {
			providers, buildFindings := buildProvidersForVet(sourced)
			report = configvet.Live(cmd.Context(), configvet.LiveInput{
				Static:    staticIn,
				Providers: providers,
			})
			report.Findings = append(buildFindings, report.Findings...)
		} else {
			report = configvet.Static(staticIn)
		}

		switch vetFormat {
		case "json":
			if err := configvet.RenderJSON(os.Stdout, report); err != nil {
				return err
			}
		case "text", "":
			configvet.RenderText(os.Stdout, report, !color.NoColor)
		default:
			return fmt.Errorf("unknown --format %q (want text or json)", vetFormat)
		}

		if report.HasErrors() || (vetStrict && len(report.Warnings()) > 0) {
			return BeQuietError{} // non-zero exit; findings already printed
		}
		return nil
	},
}

var schemaOut string

var configSchemaCmd = &cobra.Command{
	Use:   "schema [TARGET]",
	Short: "Generate JSON Schema for Talmi configuration",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		target := "config"
		if len(args) == 1 {
			target = args[0]
		}
		data, err := config.GenerateSchema(target)
		if err != nil {
			return err
		}
		data = append(data, '\n')

		if schemaOut == "" || schemaOut == "-" {
			_, err = os.Stdout.Write(data)
			return err
		}
		if err := os.WriteFile(schemaOut, data, 0o600); err != nil {
			return fmt.Errorf("writing schema: %w", err)
		}
		logSuccess("wrote %s schema to %s", target, schemaOut)
		return nil
	},
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

func init() {
	rootCmd.AddCommand(configCmd)
	configCmd.AddCommand(configVetCmd, configSchemaCmd)

	configVetCmd.Flags().BoolVar(&vetOnline, "online", false, "perform network-based checks (may be slow)")
	configVetCmd.Flags().BoolVar(&vetStrict, "strict", false, "treat warnings as errors")
	configVetCmd.Flags().StringVar(&vetFormat, "format", "text", "output format: text or json")
	configVetCmd.Flags().BoolVar(&vetLocal, "local", false, "force local config source (ignore remote)")
	configVetCmd.Flags().StringVar(&vetRef, "ref", "", "override git ref for remote config source")

	configSchemaCmd.Flags().StringVarP(&schemaOut, "out", "o", "", "output file for schema (default stdout)")
}
