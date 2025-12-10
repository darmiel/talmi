package cmd

import (
	"errors"
	"fmt"

	"github.com/spf13/viper"

	"github.com/darmiel/talmi/internal/cliconfig"
	"github.com/darmiel/talmi/pkg/client"
)

func getClient() (*client.Client, error) {
	// we need the user to provide some server address first
	server := viper.GetString(TalmiAddrKey)
	if server == "" {
		return nil, fmt.Errorf("server address not configured, provide via --server or env")
	}

	cfg, err := cliconfig.Load()
	if err != nil {
		return nil, err
	}

	var talmiToken string

	credential, err := cfg.GetCredential(server)
	if err != nil {
		if !errors.Is(err, cliconfig.ErrCredentialNotFound) {
			return nil, err
		}
	} else {
		talmiToken = credential.Token
	}

	return client.New(server, client.WithAuthToken(talmiToken)), nil
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}
