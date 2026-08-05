package configvet

import (
	"github.com/darmiel/talmi/internal/config"
	"github.com/darmiel/talmi/internal/realm"
)

// RealmRegistry builds a realm registry from realm blocks, leniently: unknown
// realm types are skipped (checkRealms reports them as CFG-REALM-TYPE) so vet
// can still evaluate the rest of the config.
func RealmRegistry(realms []config.RealmBlock) *realm.Registry {
	reg := realm.NewRegistry()
	for _, rb := range realms {
		var sem realm.Semantics
		switch rb.Type {
		case "github-app":
			sem = realm.GitHub{}
		case "artifactory":
			sem = realm.Artifactory{}
		case "talmi":
			sem = realm.Talmi{}
		default:
			continue
		}
		reg.Register(rb.Realm, sem)
	}
	return reg
}
