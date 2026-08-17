package config

var defaultRealmByType = map[string]string{
	KindGitHubApp:   "github",
	KindArtifactory: "artifactory",
	"talmi":         "talmi",
}

// DefaultRealmForType returns the default realm name for a provider type.
func DefaultRealmForType(providerType string) (name string, ok bool) {
	name, ok = defaultRealmByType[providerType]
	return name, ok
}

// DefaultedRealm records a realm block whose name was filled from its type default.
type DefaultedRealm struct {
	Type string
	Name string
}

// NormalizeRealms returns a copy of the given realms with any empty realm names filled in from their type defaults.
// It also returns a list of the realms that were filled in.
func NormalizeRealms(realms []RealmBlock) ([]RealmBlock, []DefaultedRealm) {
	out := make([]RealmBlock, len(realms))
	copy(out, realms)

	var defaulted []DefaultedRealm
	for i := range out {
		if out[i].Realm != "" {
			continue
		}
		def, ok := DefaultRealmForType(out[i].Type)
		if !ok {
			continue
		}
		out[i].Realm = def
		defaulted = append(defaulted, DefaultedRealm{
			Type: out[i].Type,
			Name: def,
		})
	}
	return out, defaulted
}
