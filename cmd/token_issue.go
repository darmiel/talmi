package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"github.com/darmiel/talmi/internal/config"
	"github.com/darmiel/talmi/internal/core"
	"github.com/darmiel/talmi/internal/engine"
	"github.com/darmiel/talmi/internal/issuers"
	"github.com/darmiel/talmi/internal/providers"
)

var (
	tokenIssueReqIssuer       string
	tokenIssueReqToken        string
	tokenIssueReqResourceType string
	tokenIssueReqResourceID   string
)

// tokenIssueCmd represents the token issue command
var tokenIssueCmd = &cobra.Command{
	Use:   "issue",
	Short: "Issue a token based on an upstream identity",
	Long:  "", // TODO
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load(cfgFile)
		if err != nil {
			return err
		}

		// initialize registries
		issuerRegistry, err := issuers.BuildRegistry(cfg.Issuers)
		if err != nil {
			return err
		}
		providerRegistry, err := providers.BuildRegistry(cfg.Providers)
		if err != nil {
			return err
		}

		eng := engine.New(cfg.Rules)

		issuer, ok := issuerRegistry[tokenIssueReqIssuer]
		if !ok {
			return fmt.Errorf("issuer '%s' not found in config", tokenIssueReqIssuer)
		}

		log.Info().Msgf("Verifying token with issuer '%s'...", tokenIssueReqIssuer)
		principal, err := issuer.Verify(cmd.Context(), tokenIssueReqToken)
		if err != nil {
			return fmt.Errorf("verification failed: %w", err)
		}
		log.Info().Msgf("Identity verified. Principals attributes: %v", principal.Attributes)

		reqResource := core.Resource{
			Type: tokenIssueReqResourceType,
			ID:   tokenIssueReqResourceID,
		}
		grant, err := eng.Evaluate(principal, reqResource)
		if err != nil {
			return fmt.Errorf("policy denied: %w", err)
		}
		log.Info().Msgf("Policy matched! Granting access via provider '%s'...", grant.Provider)

		provider, ok := providerRegistry[grant.Provider]
		if !ok {
			return fmt.Errorf("provider '%s' configured in rule but not found in registry", grant.Provider)
		}
		artifact, err := provider.Mint(cmd.Context(), principal, *grant)
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
	tokenCmd.AddCommand(tokenIssueCmd)

	tokenIssueCmd.Flags().StringVar(&tokenIssueReqIssuer, "issuer", "", "Name of the issuer (must match config)")
	tokenIssueCmd.Flags().StringVar(&tokenIssueReqToken, "token", "", "Upstream token string")
	tokenIssueCmd.Flags().StringVar(&tokenIssueReqResourceType, "resource-type", "", "Type of resource requested")
	tokenIssueCmd.Flags().StringVar(&tokenIssueReqResourceID, "resource-id", "", "ID of resource requested")

	_ = tokenIssueCmd.MarkFlagRequired("issuer")
	_ = tokenIssueCmd.MarkFlagRequired("token")
	_ = tokenIssueCmd.MarkFlagRequired("resource-type")
	_ = tokenIssueCmd.MarkFlagRequired("resource-id")
}
