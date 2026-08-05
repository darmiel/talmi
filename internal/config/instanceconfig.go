package config

import (
	"fmt"
	"sort"
	"strings"

	"github.com/darmiel/talmi/internal/secret"
)

const (
	KindGitHubApp   = "github-app"
	KindArtifactory = "artifactory"
)

var instanceConfigTypes = map[string]func() InstanceConfig{
	KindGitHubApp:   func() InstanceConfig { return &GitHubAppConfig{} },
	KindArtifactory: func() InstanceConfig { return &ArtifactoryConfig{} },
}

// InstanceTypes returns the known instance types (sorted).
func InstanceTypes() []string {
	out := make([]string, 0, len(instanceConfigTypes))
	for t := range instanceConfigTypes {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// InstanceConfig is the decoded, typed credentials/config for one provider instance.
type InstanceConfig interface {
	Validate() error
}

var _ InstanceConfig = (*GitHubAppConfig)(nil)

type GitHubAppConfig struct {
	AppID      int64      `mapstructure:"app_id" json:"app_id" jsonschema:"required"`
	PrivateKey secret.Ref `mapstructure:"private_key" json:"private_key" jsonschema:"required"`
	Server     string     `mapstructure:"server" json:"server,omitempty"`
}

func (c GitHubAppConfig) Validate() error {
	if c.AppID <= 0 {
		return fmt.Errorf("github-app instance requires 'app_id'")
	}
	if c.PrivateKey == "" {
		return fmt.Errorf("github-app instance requires 'private_key'")
	}
	return nil
}

var _ InstanceConfig = (*ArtifactoryConfig)(nil)

type ArtifactoryConfig struct {
	AdminToken secret.Ref `mapstructure:"admin_token" json:"admin_token" jsonschema:"required"`
	Groups     []string   `mapstructure:"groups" json:"groups" jsonschema:"required"`
	BaseURL    string     `mapstructure:"base_url,omitempty" json:"base_url,omitempty"`
}

func (c ArtifactoryConfig) Validate() error {
	if c.AdminToken == "" {
		return fmt.Errorf("artifactory instance requires 'admin_token'")
	}
	if len(c.Groups) == 0 {
		return fmt.Errorf("artifactory instance requires at least one 'group'")
	}
	return nil
}

func decodeInstance(realmType string, raw map[string]any) (InstanceConfig, error) {
	newCfg, ok := instanceConfigTypes[realmType]
	if !ok {
		return nil, nil // realm has no provider instances to type
	}
	target := newCfg()
	if err := strictDecode(raw, target); err != nil {
		return nil, fmt.Errorf("%s instance: %w; valid keys: %s",
			realmType, err, strings.Join(knownMapstructureTags(target), ", "))
	}
	return target, nil
}

// DecodeInstanceConfig strictly decodes raw into the typed config for realmType.
// Realm types without a provider backend (e.g. "talmi") return (nil, nil).
func DecodeInstanceConfig(realmType string, raw map[string]any) (InstanceConfig, error) {
	target, err := decodeInstance(realmType, raw)
	if err != nil || target == nil {
		return nil, err
	}
	if err := target.Validate(); err != nil {
		return nil, err
	}
	return target, nil
}
