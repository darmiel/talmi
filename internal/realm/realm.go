package realm

import "github.com/darmiel/talmi/internal/core"

// Semantics owns the meaning of one kind of realm's resources and actions.
type Semantics interface {
	// Kind is the provider kind these semantics belong to, e.g. "github-app".
	Kind() string

	// Covers reports whether the union of allows authorizes this exact request.
	// On failure, it returns a (human-readable) reason for the audit / trace.
	Covers(allows []core.Allow, req core.ResourceRequest) (ok bool, reason string)

	// CompareLevel orders two actions on the same permission for least-privilege ranking.
	// -1 if a < b, 0 if equal, +1 if a > b.
	// It returns an error when the two actions are not comparable.
	CompareLevel(a, b core.Action) (int, error)

	// ValidateResourcePattern checks that a policy allow pattern is well-formed for this kind.
	ValidateResourcePattern(pattern string) error
}

// Registry maps realm names to their semantics.
type Registry struct {
	byRealm map[string]Semantics
}

// NewRegistry returns a new empty registry.
func NewRegistry() *Registry {
	return &Registry{
		byRealm: make(map[string]Semantics),
	}
}

// Register adds a new realm and its semantics to the registry.
func (r *Registry) Register(realmName string, semantics Semantics) {
	if r.byRealm == nil {
		r.byRealm = make(map[string]Semantics)
	}
	r.byRealm[realmName] = semantics
}

func (r *Registry) Get(realmName string) (Semantics, bool) {
	semantics, ok := r.byRealm[realmName]
	return semantics, ok
}

// Kinds returns the list of known realm kinds.
func Kinds() []string {
	return []string{KindGitHub, KindArtifactory, KindTalmi}
}

// SemanticsFor returns the semantics for a given realm kind, if known.
func SemanticsFor(kind string) (Semantics, bool) {
	switch kind {
	case KindGitHub:
		return GitHub{}, true
	case KindArtifactory:
		return Artifactory{}, true
	case KindTalmi:
		return Talmi{}, true
	default:
		return nil, false
	}
}
