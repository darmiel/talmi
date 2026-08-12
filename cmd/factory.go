package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/viper"

	"github.com/darmiel/talmi/internal/cliconfig"
	"github.com/darmiel/talmi/pkg/client"
)

type Factory struct {
	// RemoteAddr is the address of the Talmi server to connect to.
	RemoteAddr string

	CLIConfigPath string
	LogLevel      string
	LogFormat     string

	// Command-specific flags
	PolicyPath string // contains the "main" Talmi configuration => rules and policies used for minting
}

func NewFactory() *Factory {
	return &Factory{}
}

func (f *Factory) GetRemoteAddr() (string, error) {
	server := f.RemoteAddr // prio 1: command-line flag
	if server == "" {
		server = viper.GetString(TalmiAddrKey) // prio 2: config/env
	}
	if server == "" {
		return "", fmt.Errorf("server address not configured (use --server or set TALMI_ADDR)")
	}
	return server, nil
}

// GetClient returns an authenticated HTTP client for remote operations.
func (f *Factory) GetClient() (*client.Client, error) {
	server, err := f.GetRemoteAddr()
	if err != nil {
		return nil, err
	}
	var token string
	if cfg, err := cliconfig.Load(); err == nil {
		if cred, err := cfg.GetCredential(server); err == nil { // token prio 1: saved credential
			token = cred.Token
		}
	}

	if envToken := os.Getenv("TALMI_TOKEN"); envToken != "" { // token prio 2: env var
		token = envToken
	}

	return client.New(server, client.WithAuthToken(token)), nil
}
