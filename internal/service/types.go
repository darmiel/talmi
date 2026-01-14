package service

import "github.com/darmiel/talmi/internal/core"

type IssueRequest struct {
	// Token is the raw upstream (OIDC) token
	Token string

	// RequestedIssuer is optional. If empty, auto-discovery is attempted.
	RequestedIssuer string

	// RequestedProvider is optional. If empty, the policy engine decides.
	RequestedProvider string

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
