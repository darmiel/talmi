package config

import (
	"fmt"
)

// ProviderSpec is one fully-resolved provider instance.
type ProviderSpec struct {
	Name       string
	Realm      string
	Type       string
	Capability CapabilityBlock
	Config     InstanceConfig
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

			cfg, err := decodeInstance(rb.Type, inst.Config)
			if err != nil {
				return nil, fmt.Errorf("realm %q instance %q: %w", rb.Realm, inst.Name, err)
			}

			specs = append(specs, ProviderSpec{
				Name:       inst.Name,
				Realm:      rb.Realm,
				Type:       rb.Type,
				Capability: capability,
				Config:     cfg,
			})
		}
	}

	return specs, nil
}
