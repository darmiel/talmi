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
		if sem, ok := realm.SemanticsFor(rb.Type); ok {
			reg.Register(rb.Realm, sem)
		}
	}
	return reg
}
