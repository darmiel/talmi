package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"github.com/darmiel/talmi/internal/config"
	"github.com/darmiel/talmi/internal/core"
	"github.com/darmiel/talmi/internal/providers"
)

var (
	mintTargetFile string
	mintRuleName   string
)

// mintCmd represents the mint command
var mintCmd = &cobra.Command{
	Use:   "mint",
	Short: "Mint a token from an upstream identity token",
	Long:  "", // TODO
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load(mintTargetFile)
		if err != nil {
			return err
		}

		var targetRule *core.Rule
		for _, rule := range cfg.Rules {
			if rule.Name == mintRuleName {
				targetRule = &rule
				break
			}
		}
		if targetRule == nil {
			return fmt.Errorf("rule '%s' not found in config", mintRuleName)
		}
		grant := targetRule.Grant

		providerRegistry, err := providers.BuildRegistry(cfg.Providers, nil)
		if err != nil {
			return fmt.Errorf("failed to build provider registry: %w", err)
		}

		provider, ok := providerRegistry[grant.Provider]
		if !ok {
			return fmt.Errorf("provider '%s' configured in rule but not found in registry", grant.Provider)
		}

		dummyPrincipal := &core.Principal{
			ID:         "dummy-principal",
			Issuer:     "dummy-issuer",
			Attributes: map[string]any{},
		}
		artifact, err := provider.Mint(cmd.Context(), dummyPrincipal, grant)
		if err != nil {
			return fmt.Errorf("minting failed: %w", err)
		}
		log.Info().Msgf("Minted token!")

		enc := json.NewEncoder(log.Logger)
		enc.SetIndent("", "  ")
		return enc.Encode(artifact)
	},
}

func init() {
	rootCmd.AddCommand(mintCmd)

	mintCmd.Flags().StringVarP(&mintTargetFile, "target", "f", "", "The Talmi config file to use")
	mintCmd.Flags().StringVarP(&mintRuleName, "rule", "r", "", "The specific rule to use for minting")

	_ = mintCmd.MarkFlagRequired("target")
	_ = mintCmd.MarkFlagRequired("rule")
}
