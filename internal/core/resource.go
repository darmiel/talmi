package core

import "strings"

// Resource is a realm-prefixed identifier of the form "<realm>:<body>".
// The core routes a resources to a provider by its realm. The body is opaque to the core
// and is interpreted only by the realm's provider.
// Example for GitHub: github:owner/repo
type Resource string

// Action is an opaque realm-defined capability, like "contents:write" (GitHub permission).
type Action string

// Realm returns the contents after the first colon
func (r Resource) Realm() (string, bool) {
	i := strings.IndexByte(string(r), ':')
	if i < 0 {
		return "", false
	}
	return string(r[:i]), true
}

// Body returns the contents after the first colon
func (r Resource) Body() (string, bool) {
	i := strings.IndexByte(string(r), ':')
	if i < 0 {
		return "", false
	}
	return string(r[i+1:]), true
}

// ResourceRequest is one requested resource together with the actions wanted on it.
// A single resource often needs several actions at once (e.g. contents:write + actions:write)
type ResourceRequest struct {
	Resource Resource `json:"resource"`
	Actions  []Action `json:"actions"`
}

// Allow is one policy allowance block used inside a Rule.
// Resources are patterns matched by the realm semantics.
type Allow struct {
	Resources []string `json:"resources"` // note that it's a string, because it may contain matchers
	Actions   []Action
}
