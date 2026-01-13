package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

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
	issueReqToken    string
	issueReqIssuer   string
	issueReqProvider string
	issueTargetFile  string
	issuePermissions []string
)

var issueCmd = &cobra.Command{
	Use:   "issue",
	Short: "Request an artifact (i.e. token) from Talmi",
	Long: `Exchanges an upstream identity token for a downstream resource token.

Modes:
  1. Remote (Default): Contacts the configured Talmi server.
  2. Standalone (--config): Loads a local config file and processes the request locally.`,
	Example: `  # Remote Issue (uses TALMI_ADDR)
  talmi issue --token $JWT
  
  # Issue locally
  talmi issue -f talmi.yaml --token $JWT`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if issueTargetFile != "" {
			// if -f is passed, handle it locally
			log.Debug().Msg("Running 'issue' command in local mode")
			return issueTokenLocally(cmd, args)
		}
		// otherwise, expect to issue from remote server
		log.Debug().Msg("Running 'issue' command in remote mode")
		return issueTokenRemote(cmd, args)
	},
}

func init() {
	rootCmd.AddCommand(issueCmd)

	issueCmd.Flags().StringVarP(&issueTargetFile, "config", "f", "", "Run locally using this config file")
	issueCmd.Flags().StringVarP(&issueReqToken, "token", "t", "", "Upstream OIDC token")
	issueCmd.Flags().StringVar(&issueReqIssuer, "issuer", "", "Explicit issuer name (optional)")
	issueCmd.Flags().StringVar(&issueReqProvider, "provider", "", "Requested provider name (optional)")
	issueCmd.Flags().StringArrayVar(&issuePermissions, "permission", []string{}, "Requested permission in key=value format (can be specified multiple times)")

	_ = issueCmd.MarkFlagRequired("token")
}

func getPermissionsMap() (map[string]string, error) {
	var permissions map[string]string
	if len(issuePermissions) > 0 {
		permissions = make(map[string]string)
		for _, perm := range issuePermissions {
			s := strings.SplitN(perm, "=", 2)
			if len(s) != 2 {
				return nil, fmt.Errorf("invalid permission format: %s, expected key=value", perm)
			}
			permissions[s[0]] = s[1]
		}
	}
	return permissions, nil
}

func issueTokenRemote(cmd *cobra.Command, _ []string) error {
	cli, err := getClient()
	if err != nil {
		return err
	}

	permissions, err := getPermissionsMap()
	if err != nil {
		return err
	}

	log.Info().Msgf("Requesting to mint artifact...")
	artifact, err := cli.IssueToken(cmd.Context(), issueReqToken, client.IssueTokenOptions{
		RequestedProvider: issueReqProvider,
		RequestedIssuer:   issueReqIssuer,
		Permissions:       permissions,
	})
	if err != nil {
		return err
	}

	log.Info().Msgf("Successfully retrieved artifact:")
	enc := json.NewEncoder(os.Stderr)
	enc.SetIndent("", "  ")
	return enc.Encode(artifact)
}

func issueTokenLocally(cmd *cobra.Command, _ []string) error {
	cfg, err := config.Load(issueTargetFile)
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

	permissions, err := getPermissionsMap()
	if err != nil {
		return err
	}

	eng := engine.New(cfg.Rules)
	var iss core.Issuer

	// if an issuer was passed, use it
	if issueReqIssuer != "" {
		issuerByName, ok := issuerRegistry.Get(issueReqIssuer)
		if !ok {
			return fmt.Errorf("issuer '%s' not found in config", issueReqIssuer)
		}
		iss = issuerByName
	} else {
		// otherwise use the discovery service to find the corresponding issuer
		issuerByURL, err := issuerRegistry.IdentifyIssuer(issueReqToken)
		if err != nil {
			return fmt.Errorf("cannot determine issue from URL: %w", err)
		}
		iss = issuerByURL
	}
	log.Debug().Msgf("Using issuer: '%s'", iss.Name())

	// validate the (OIDC) token and return principal
	log.Info().Msgf("Verifying token with issuer '%s'...", issueReqIssuer)
	principal, err := iss.Verify(cmd.Context(), issueReqToken)
	if err != nil {
		return fmt.Errorf("verification failed: %w", err)
	}
	log.Info().Msgf("Identity verified. Principals attributes: %v", principal.Attributes)

	rule, err := eng.Evaluate(principal, issueReqProvider)
	if err != nil {
		return fmt.Errorf("policy denied: %w", err)
	}
	grant := rule.Grant

	log.Info().Msgf("Policy matched in rule '%s'! Minting '%s'...", rule.Name, grant.Provider)

	provider, ok := providerRegistry[grant.Provider]
	if !ok {
		return fmt.Errorf("provider '%s' configured in rule but not found in registry", grant.Provider)
	}

	effectivePermissions, err := provider.Downscope(grant.Permissions, permissions)
	if err != nil {
		return fmt.Errorf("downscoping permissions failed: %w", err)
	}

	effectiveGrant := grant
	effectiveGrant.Permissions = effectivePermissions

	artifact, err := provider.Mint(cmd.Context(), principal, effectiveGrant)
	if err != nil {
		return fmt.Errorf("minting failed: %w", err)
	}
	log.Info().Msgf("Minted token!")

	enc := json.NewEncoder(log.Logger)
	enc.SetIndent("", "  ")
	return enc.Encode(artifact)
}
