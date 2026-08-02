package config

import (
	"fmt"

	"github.com/darmiel/talmi/internal/secret"
)

// ProviderSpec is one fully-resolved provider instance.
type ProviderSpec struct {
	Name       string
	Realm      string
	Type       string
	Server     string
	BaseURL    string
	Capability CapabilityBlock
	AppID      int64
	PrivateKey secret.Ref
	AdminToken secret.Ref
	Groups     []string
}

// ExpandProviders flattens realm blocks into per-instance provider specs,
// applying realm-level capability defaults unless the instance overrides them.
func ExpandProviders(realms []RealmBlock) ([]ProviderSpec, error) {
	var specs []ProviderSpec
	seen := make(map[string]struct{})

	for _, rb := range realms {
		if rb.Realm == "" {
			return nil, fmt.Errorf("realm block is missing a realm name")
		}
		if rb.Type == "" {
			return nil, fmt.Errorf("realm block %q is missing a type", rb.Realm)
		}
		for _, inst := range rb.Instances {
			if inst.Name == "" {
				return nil, fmt.Errorf("realm %q has an instance with no name", rb.Realm)
			}
			if _, ok := seen[inst.Name]; ok {
				return nil, fmt.Errorf("duplicate provider instance name %q", inst.Name)
			}
			seen[inst.Name] = struct{}{}

			capability := rb.Capability
			if inst.Capability.isSet() {
				capability = inst.Capability
			}

			specs = append(specs, ProviderSpec{
				Name:       inst.Name,
				Realm:      rb.Realm,
				Type:       rb.Type,
				Server:     rb.Server,
				BaseURL:    rb.BaseURL,
				Capability: capability,
				AppID:      inst.AppID,
				PrivateKey: inst.PrivateKey,
				AdminToken: inst.AdminToken,
				Groups:     inst.Groups,
			})
		}
	}

	return specs, nil
}
