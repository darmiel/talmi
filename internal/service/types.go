package service

import "github.com/darmiel/talmi/internal/core"

type IssueRequest struct {
	// Token is the raw upstream (OIDC) token
	Token string

	// RequestedIssuer is optional. If empty, auto-discovery is attempted.
	RequestedIssuer string

	// RequestedTargets is optional but when omitted, the provider must be able to infer them.
	RequestedTargets []core.Target

	// RequestedPermissions allow downscoping.
	RequestedPermissions map[string]string
}

type IssueResponse struct {
	// Artifact is the issued token artifact.
	Artifact *core.TokenArtifact

	// Principal is the principal associated with the issued token.
	// We return it for auditing if needed by caller
	Principal *core.Principal

	// Rule is the policy rule that authorized this issuance.
	Rule *core.Rule
}

type ExplainRequest struct {
	Token    string
	ReplayID string // if set, token is ignored and identity is loaded from audit log

	// Context overrides
	RequestedIssuer string
	Targets         []core.Target
}
