package core

// Decision is the outcome of authorizing a set of [ResourceRequest]s again the policy engine.
type Decision struct {
	// Authorized is true only if every requested resource + action is covered by the union of matching rules.
	Authorized bool `json:"authorized"`

	// PolicyNames are the rules that matched the principal.
	PolicyNames []string `json:"policy_names"`

	// PerRequest is the coverage outcome for each requested resource.
	PerRequest []RequestDecision `json:"per_request"`
}

// RequestDecision is records whether one requested resource was authorized.
type RequestDecision struct {
	Request ResourceRequest `json:"request"`
	Covered bool            `json:"covered"`
	// Reason explains a non-coverage (empty if Covered)
	Reason string `json:"reason,omitempty"`
}
