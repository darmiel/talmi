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
	"github.com/darmiel/talmi/pkg/client"
)

var (
	tokenIssueReqIssuer   string
	tokenIssueReqToken    string
	tokenIssueReqProvider string

	tokenIssueTargetFile string
)

func issueTokenRemote(cmd *cobra.Command, _ []string) error {
	cli, err := getClient()
	if err != nil {
		return err
	}

	log.Info().Msgf("Requesting to mint artifact...")
	artifact, err := cli.IssueToken(cmd.Context(), tokenIssueReqToken, client.IssueTokenOptions{
		RequestedProvider: tokenIssueReqProvider,
		RequestedIssuer:   tokenIssueReqIssuer,
	})
	if err != nil {
		return err
	}

	log.Info().Msgf("Successfully retrieved artifact:")
	enc := json.NewEncoder(log.Logger)
	enc.SetIndent("", "  ")
	return enc.Encode(artifact)
}

func issueTokenLocally(cmd *cobra.Command, _ []string) error {
	cfg, err := config.Load(tokenIssueTargetFile)
	if err != nil {
		return err
	}

	// initialize registries
	issuerRegistry, err := issuers.BuildRegistry(cmd.Context(), cfg.Issuers)
	if err != nil {
		return err
	}
	providerRegistry, err := providers.BuildRegistry(cfg.Providers, nil)
	if err != nil {
		return err
	}

	eng := engine.New(cfg.Rules)
	var iss core.Issuer

	// if an issuer was passed, use it
	if tokenIssueReqIssuer != "" {
		issuerByName, ok := issuerRegistry.Get(tokenIssueReqIssuer)
		if !ok {
			return fmt.Errorf("issuer '%s' not found in config", tokenIssueReqIssuer)
		}
		iss = issuerByName
	} else {
		// otherwise use the discovery service to find the corresponding issuer
		issuerByURL, err := issuerRegistry.IdentifyIssuer(tokenIssueReqToken)
		if err != nil {
			return fmt.Errorf("cannot determine issue from URL: %w", err)
		}
		iss = issuerByURL
	}
	log.Debug().Msgf("Using issuer: '%s'", iss.Name())

	// validate the (OIDC) token and return principal
	log.Info().Msgf("Verifying token with issuer '%s'...", tokenIssueReqIssuer)
	principal, err := iss.Verify(cmd.Context(), tokenIssueReqToken)
	if err != nil {
		return fmt.Errorf("verification failed: %w", err)
	}
	log.Info().Msgf("Identity verified. Principals attributes: %v", principal.Attributes)

	rule, grant, err := eng.Evaluate(principal, tokenIssueReqProvider)
	if err != nil {
		return fmt.Errorf("policy denied: %w", err)
	}
	log.Info().Msgf("Policy matched in rule '%s'! Minting '%s'...", rule.Name, grant.Provider)

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
}

// tokenIssueCmd represents the token issue command
var tokenIssueCmd = &cobra.Command{
	Use:   "issue",
	Short: "Issue a token based on an upstream identity",
	Long:  "", // TODO
	RunE: func(cmd *cobra.Command, args []string) error {
		if tokenIssueTargetFile != "" {
			// if -f is passed, handle it locally
			return issueTokenLocally(cmd, args)
		}
		// otherwise, expect to issue from remote server
		return issueTokenRemote(cmd, args)
	},
}

func init() {
	rootCmd.AddCommand(tokenIssueCmd)

	tokenIssueCmd.Flags().StringVarP(&tokenIssueTargetFile, "target", "f", "", "The Talmi config file to use")

	tokenIssueCmd.Flags().StringVar(&tokenIssueReqIssuer, "issuer", "", "Name of the issuer (must match config)")
	tokenIssueCmd.Flags().StringVarP(&tokenIssueReqToken, "token", "t", "", "Upstream token string")
	tokenIssueCmd.Flags().StringVar(&tokenIssueReqProvider, "provider", "", "Provider requested")

	_ = tokenIssueCmd.MarkFlagRequired("token")
}
