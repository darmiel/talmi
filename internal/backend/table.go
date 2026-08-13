package backend

import (
	"fmt"

	"github.com/darmiel/talmi/internal/config"
	"github.com/darmiel/talmi/internal/core"
	githubprovider "github.com/darmiel/talmi/internal/providers/github"
	"github.com/darmiel/talmi/internal/providers/jfrog"
	"github.com/darmiel/talmi/internal/realm"
	"github.com/darmiel/talmi/internal/secret"
)

var backends = []Backend{
	{
		Type:                 config.KindGitHubApp,
		Semantics:            realm.GitHub{},
		SupportsAPIDiscovery: true,
		Build: func(input BuildInput) (core.ResourceProvider, error) {
			c, ok := input.Spec.Config.(*config.GitHubAppConfig)
			if !ok {
				return nil, fmt.Errorf("github-app: unexpected config %T", input.Spec.Config)
			}
			key, err := secret.Resolve(c.PrivateKey)
			if err != nil {
				return nil, err
			}
			return githubprovider.New(input.Spec.Name, input.Spec.Realm, githubprovider.ProviderConfig{
				AppID:           c.AppID,
				PrivateKey:      key,
				ServerBaseURL:   c.Server,
				RefreshInterval: input.Spec.Capability.Refresh,
			})
		},
	},
	{
		Type:                 config.KindArtifactory,
		Semantics:            realm.Artifactory{},
		SupportsAPIDiscovery: false,
		Build: func(input BuildInput) (core.ResourceProvider, error) {
			c, ok := input.Spec.Config.(*config.ArtifactoryConfig)
			if !ok {
				return nil, fmt.Errorf("artifactory: unexpected config %T", input.Spec.Config)
			}
			tok, err := secret.ResolveString(c.AdminToken)
			if err != nil {
				return nil, err
			}
			return jfrog.New(input.Spec.Name, input.Spec.Realm, jfrog.ProviderConfig{
				Server:     c.BaseURL,
				Token:      tok,
				Groups:     c.Groups,
				Resources:  input.Spec.Capability.Resources,
				MaxActions: input.Spec.Capability.MaxActions,
			})
		},
	},
}
