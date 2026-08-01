package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/rs/xid"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/darmiel/talmi/internal/core"
	"github.com/darmiel/talmi/internal/correlation"
	"github.com/darmiel/talmi/internal/engine"
	"github.com/darmiel/talmi/internal/resolver"
)

// TokenService orchestrates the issuance pipeline:
// verify -> authorize -> resolve/mint -> persist -> audit
type TokenService struct {
	issuers       IssuerResolver
	policyManager *engine.PolicyManager
	resolver      *resolver.Resolver
	leaseStore    core.LeaseStore
	auditor       core.Auditor
}

func NewTokenService(
	issuers IssuerResolver,
	policyManager *engine.PolicyManager,
	res *resolver.Resolver,
	leaseStore core.LeaseStore,
	auditor core.Auditor,
) *TokenService {
	return &TokenService{
		issuers:       issuers,
		policyManager: policyManager,
		resolver:      res,
		leaseStore:    leaseStore,
		auditor:       auditor,
	}
}

func (s *TokenService) IssueLease(ctx context.Context, req IssueRequest) (*IssueResponse, error) {
	logger := log.Ctx(ctx)
	leaseID := correlation.From(ctx)
	if leaseID == "" {
		leaseID = xid.New().String()
	}

	entry := core.AuditEntry{
		ID:     leaseID,
		Time:   time.Now(),
		Action: "lease.issue",
	}
	defer func() {
		if err := s.auditor.Log(entry); err != nil {
			logger.Error().Err(err).Msg("failed to write audit log entry for lease issuance")
		}
	}()

	if len(req.Resources) == 0 {
		entry.Error = "no resources requested"
		return nil, httpError(http.StatusBadRequest, fmt.Errorf("no resources requested"))
	}

	// first we need to identify the issuer that we use to create the principal
	issuer, err := s.selectIssuer(req)
	if err != nil {
		entry.Error = "issuer selection failed"
		entry.Stacktrace = err.Error()
		return nil, httpError(http.StatusUnauthorized, fmt.Errorf("verification failed: %w", err))
	}
	principal, err := issuer.Verify(ctx, req.Token)
	if err != nil {
		entry.Error = "verification failed"
		entry.Stacktrace = err.Error()
		return nil, httpError(http.StatusUnauthorized, fmt.Errorf("verification failed: %w", err))
	}
	entry.Principal = principal

	logger.UpdateContext(func(c zerolog.Context) zerolog.Context {
		return c.Str("sub", principal.ID)
	})

	// now that we have verified the principal, we can continue with authorizing the requested resources
	decision := s.policyManager.GetEngine().Authorize(principal, req.Resources)
	if !decision.Authorized {
		// one or more of the requested resources were denied
		entry.Success = false
		entry.Error = "policy denied"
		dr := denyReason(decision)
		entry.Stacktrace = dr
		return nil, httpError(http.StatusForbidden, fmt.Errorf("policy denied: %s", dr))
	}
	entry.PolicyName = strings.Join(decision.PolicyNames, ",")

	// now resolve + mint (and roll back if partial)
	minted, err := s.resolver.Resolve(ctx, principal, req.Resources)
	if err != nil {
		entry.Error = "resolution failed"
		entry.Stacktrace = err.Error()
		return nil, httpError(http.StatusInternalServerError, fmt.Errorf("resolving: %w", err))
	}

	secret, err := revocationSecretFor(minted)
	if err != nil {
		s.rollback(ctx, minted)
		return nil, httpError(http.StatusInternalServerError, fmt.Errorf("generating revocation secret: %w", err))
	}

	lease := core.Lease{
		ID:               leaseID,
		PrincipalID:      principal.ID,
		Issuer:           principal.Issuer,
		PolicyNames:      decision.PolicyNames,
		CreatedAt:        time.Now(),
		RevocationSecret: secret,
	}
	resp := &IssueResponse{
		LeaseID:          leaseID,
		RevocationSecret: secret,
	}
	for _, m := range minted {
		lease.Artifacts = append(lease.Artifacts, core.LeasedArtifact{
			Provider:     m.Provider,
			Realm:        m.Realm,
			Covers:       m.Covers,
			Fingerprint:  m.Artifact.Fingerprint,
			ExpiresAt:    m.Artifact.ExpiresAt,
			Revocable:    m.Revocable,
			RevocationID: m.RevocationID,
			Metadata:     m.Artifact.Metadata,
		})
		resp.Artifacts = append(resp.Artifacts, IssuedArtifact{
			Provider:    m.Provider,
			Realm:       m.Realm,
			Covers:      m.Covers,
			Token:       m.Artifact.Value,
			Fingerprint: m.Artifact.Fingerprint,
			ExpiresAt:   m.Artifact.ExpiresAt,
			Metadata:    m.Artifact.Metadata,
		})
	}

	if err := s.leaseStore.SaveLease(ctx, lease); err != nil {
		s.rollback(ctx, minted)
		entry.Error = "persisting lease failed"
		entry.Stacktrace = err.Error()
		return nil, httpError(http.StatusInternalServerError, fmt.Errorf("persisting lease: %w", err))
	}

	entry.Success = true
	if len(minted) > 0 {
		entry.TokenFingerprint = minted[0].Artifact.Fingerprint // TODO
	}
	return resp, nil
}

func (s *TokenService) selectIssuer(req IssueRequest) (core.Issuer, error) {
	if req.RequestedIssuer != "" {
		issuer, ok := s.issuers.Get(req.RequestedIssuer)
		if !ok {
			return nil, fmt.Errorf("requested issuer '%s' not found", req.RequestedIssuer)
		}
		return issuer, nil
	}
	issuer, err := s.issuers.IdentifyIssuer(req.Token)
	if err != nil {
		return nil, fmt.Errorf("issuer auto-discovery failed: %w", err)
	}
	return issuer, nil
}

func (s *TokenService) rollback(ctx context.Context, minted []resolver.Minted) {
	logger := log.Ctx(ctx)
	for _, m := range minted {
		if !m.Revocable {
			continue
		}
		if err := s.resolver.Revoke(ctx, m.Provider, m.RevocationID, m.Artifact.Value); err != nil {
			logger.Error().Err(err).
				Str("provider", m.Provider).
				Msg("rollback revoke failed")
		}
	}
}

func denyReason(d core.Decision) string {
	var reasons []string
	for _, rd := range d.PerRequest {
		if !rd.Covered {
			reasons = append(reasons, fmt.Sprintf("%s: %s", rd.Request.Resource, rd.Reason))
		}
	}
	return strings.Join(reasons, "; ")
}

func revocationSecretFor(minted []resolver.Minted) (string, error) {
	for _, m := range minted {
		if m.Revocable {
			return randomSecret()
		}
	}
	return "", nil // nothing revocable
}

func randomSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("crypto error: %w", err)
	}
	return hex.EncodeToString(b), nil
}
