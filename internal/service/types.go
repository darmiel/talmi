package service

import (
	"time"

	"github.com/darmiel/talmi/internal/core"
)

// IssueRequest is a request to mint a lease of resource tokens.
type IssueRequest struct {
	// Token is the raw upstream (OIDC) token
	Token string

	// RequestedIssuer is optional. If empty, auto-discovery is attempted.
	RequestedIssuer string

	// Resources is the list of requested resources and actions.
	Resources []core.ResourceRequest
}

type IssueResponse struct {
	// LeaseID is the ID of the issued lease.
	LeaseID string

	// RevocationSecret is the secret used to revoke the lease.
	// Empty if the lease is not revocable.
	RevocationSecret string

	// Artifacts is the list of issued token artifacts.
	Artifacts []IssuedArtifact
}

// IssuedArtifact is one minted token as returned to the caller.
type IssuedArtifact struct {
	ArtifactID                 string
	RequiresTokenForRevocation bool
	Provider                   string
	Realm                      string
	Covers                     []core.ResourceRequest
	Token                      string // the secret token value (not stored)
	Fingerprint                string
	ExpiresAt                  time.Time
	Metadata                   map[string]any
}

// IssuerResolver is the subset of the issuer registry the service consumes.
// Used mainly for testing.
type IssuerResolver interface {
	Get(name string) (core.Issuer, bool)
	IdentifyIssuer(token string) (core.Issuer, error)
}

// RevokeRequest revokes a lease.
type RevokeRequest struct {
	RevocationSecret string
	Tokens           map[string]string // artifact ID -> token value
}

// RevokeResponse reports which artifacts were revoked.
type RevokeResponse struct {
	LeaseID string
	Revoked []string
}
