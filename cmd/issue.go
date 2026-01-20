package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"github.com/darmiel/talmi/internal/service"
	"github.com/darmiel/talmi/pkg/client"
)

var (
	issueReqIssuer   string
	issueReqProvider string
	issueTargetFile  string
	issuePermissions []string
	issueRawOutput   bool
)

var issueCmd = &cobra.Command{
	Use:   "issue TOKEN",
	Short: "Request to mint an artifact (i.e. token) from Talmi",
	Long: `Exchanges an upstream identity token for a downstream resource token.

Modes:
  1. Remote (Default): Contacts the configured Talmi server.
  2. Standalone (--config): Loads a local config file and processes the request locally.`,
	Example: `  # Remote Issue (uses TALMI_ADDR)
  talmi issue TOKEN
  
  # Issue locally
  talmi issue -f talmi.yaml TOKEN`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		permissions, err := getPermissionsMap()
		if err != nil {
			return err
		}
		token := args[0]
		if token == "" {
			return fmt.Errorf("token cannot be empty")
		}
		if issueTargetFile != "" {
			// if -f is passed, handle it locally
			log.Debug().Msg("Running 'issue' command in local mode")
			return issueTokenLocally(cmd, token, permissions)
		}
		// otherwise, expect to issue from remote server
		log.Debug().Msg("Running 'issue' command in remote mode")
		return issueTokenRemote(cmd, token, permissions)
	},
}

func init() {
	rootCmd.AddCommand(issueCmd)

	issueCmd.Flags().StringVarP(&issueTargetFile, "config", "f", "", "Run locally using this config file")
	issueCmd.Flags().StringVar(&issueReqIssuer, "issuer", "", "Explicit issuer name (optional)")
	issueCmd.Flags().StringVar(&issueReqProvider, "provider", "", "Requested provider name (optional)")
	issueCmd.Flags().StringArrayVar(&issuePermissions, "permission", []string{}, "Requested permission in key=value format (can be specified multiple times)")
	issueCmd.Flags().BoolVarP(&issueRawOutput, "raw", "r", false, "Only output raw token without formatting")

	_ = issueCmd.MarkFlagRequired("token")
}

func issueTokenRemote(cmd *cobra.Command, token string, permissions map[string]string) error {
	cli, err := f.GetClient()
	if err != nil {
		return err
	}

	log.Debug().Msgf("Requesting to mint artifact...")
	artifact, correlationID, err := cli.IssueToken(cmd.Context(), token, client.IssueTokenOptions{
		RequestedProvider: issueReqProvider,
		RequestedIssuer:   issueReqIssuer,
		Permissions:       permissions,
	})
	if err != nil {
		log.Error().Msgf("%s failed to retrieve artifact (correlation ID: %s)", redCross, correlationID)
		log.Error().Msgf("error: %v", err)
		return BeQuietError{}
	}

	if issueRawOutput {
		fmt.Println(artifact.Value)
		return nil
	}

	log.Info().Msgf("%s successfully retrieved artifact (%s)", greenCheck, faint(correlationID))
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(artifact)
}

func issueTokenLocally(cmd *cobra.Command, token string, permissions map[string]string) error {
	svc, err := f.GetLocalService(cmd.Context())
	if err != nil {
		return err
	}

	result, err := svc.IssueToken(cmd.Context(), service.IssueRequest{
		Token:                token,
		RequestedIssuer:      issueReqIssuer,
		RequestedProvider:    issueReqProvider,
		RequestedPermissions: permissions,
	})
	if err != nil {
		log.Error().Msgf("%s local issuance failed", redCross)
		log.Error().Msgf("error: %v", err)
		return BeQuietError{}
	}

	if issueRawOutput {
		fmt.Println(result.Artifact.Value)
		return nil
	}

	log.Info().Msgf("%s successfully issued artifact", greenCheck)
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(result.Artifact)
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
