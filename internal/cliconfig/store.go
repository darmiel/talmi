package cliconfig

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
)

var ErrCredentialNotFound = fmt.Errorf("credential not found")

type Credential struct {
	Token string
}

type CLIConfig struct {
	Credentials map[string]*Credential
}

func GetConfigPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("getting user home directory: %w", err)
	}
	return filepath.Join(home, ".talmi", "config.json"), nil
}

func Load() (*CLIConfig, error) {
	path, err := GetConfigPath()
	if err != nil {
		return nil, err
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening config file '%s': %w", path, err)
	}
	defer func(f *os.File) {
		_ = f.Close()
	}(f)

	var cfg CLIConfig
	if err := json.NewDecoder(f).Decode(&cfg); err != nil {
		return nil, fmt.Errorf("decoding config file '%s': %w", path, err)
	}
	return &cfg, nil
}

func Save(cfg *CLIConfig) error {
	path, err := GetConfigPath()
	if err != nil {
		return err
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("creating config directory '%s': %w", dir, err)
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("opening config file '%s' for writing: %w", path, err)
	}
	defer func(f *os.File) {
		_ = f.Close()
	}(f)

	if err := json.NewEncoder(f).Encode(cfg); err != nil {
		return fmt.Errorf("encoding config to file '%s': %w", path, err)
	}
	return nil
}

func (c *CLIConfig) GetCredential(server string) (*Credential, error) {
	u, err := url.Parse(server)
	if err != nil {
		return nil, fmt.Errorf("parsing server URL '%s': %w", server, err)
	}
	cred, ok := c.Credentials[u.Host]
	if !ok {
		return nil, ErrCredentialNotFound
	}
	return cred, nil
}
