package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/rs/xid"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/darmiel/talmi/internal/audit"
	"github.com/darmiel/talmi/internal/core"
	"github.com/darmiel/talmi/internal/engine"
	"github.com/darmiel/talmi/internal/resolver"
)

type recorder interface {
	Record(ctx context.Context, action core.AuditAction, outcome core.Outcome, opts ...audit.Option) error
}

// TokenService orchestrates the issuance pipeline:
// verify -> authorize -> resolve/mint -> persist -> audit
type TokenService struct {
	issuers       IssuerResolver
	policyManager *engine.PolicyManager
	resolver      *resolver.Resolver
	leaseStore    core.LeaseStore
	recorder      recorder
	revision      string
}

type ExplainResponse struct {
	Principal *core.Principal
	Decision  core.Decision
}

func NewTokenService(
	issuers IssuerResolver,
	policyManager *engine.PolicyManager,
	res *resolver.Resolver,
	leaseStore core.LeaseStore,
	recorder recorder,
	revision string,
) *TokenService {
	return &TokenService{
		issuers:       issuers,
		policyManager: policyManager,
		resolver:      res,
		leaseStore:    leaseStore,
		recorder:      recorder,
		revision:      revision,
	}
}

func (s *TokenService) IssueLease(ctx context.Context, req IssueRequest) (*IssueResponse, error) {
	logger := log.Ctx(ctx)
	leaseID := xid.New().String()

	var (
		principal *core.Principal
		decision  *core.Decision
		artifacts []core.ArtifactAudit
		outcome   = core.OutcomeFailure
		auditErr  error
	)
	defer func() {
		opts := []audit.Option{
			audit.WithActor(principal),
			audit.WithRevision(s.revision),
			audit.WithMetadata(map[string]any{"lease_id": leaseID}),
			audit.WithError(auditErr),
		}
		if decision != nil {
			opts = append(opts, audit.WithDecision(decision))
		}
		if len(artifacts) > 0 {
			opts = append(opts, audit.WithArtifacts(artifacts))
		}
		if err := s.recorder.Record(ctx, core.ActionLeaseIssue, outcome, opts...); err != nil {
			logger.Error().Err(err).Msg("failed to write audit log entry for lease issuance")
		}
	}()

	if len(req.Resources) == 0 {
		auditErr = fmt.Errorf("no resources requested")
		return nil, httpError(http.StatusBadRequest, auditErr)
	}

	// first we need to identify the issuer that we use to create the principal
	issuer, err := s.selectIssuer(req)
	if err != nil {
		auditErr = fmt.Errorf("issuer selection failed: %w", err)
		return nil, httpError(http.StatusUnauthorized, auditErr)
	}
	principal, err = issuer.Verify(ctx, req.Token)
	if err != nil {
		auditErr = fmt.Errorf("verification failed: %w", err)
		return nil, httpError(http.StatusUnauthorized, auditErr)
	}

	logger.UpdateContext(func(c zerolog.Context) zerolog.Context {
		return c.Str("sub", principal.ID)
	})

	logger.Debug().
		Str("issuer", principal.Issuer).
		Msg("principal verified")

	// now that we have verified the principal, we can continue with authorizing the requested resources
	decision = new(s.policyManager.GetEngine().Authorize(principal, req.Resources))

	logger.Debug().
		Int("requests", len(req.Resources)).
		Bool("authorized", decision.Authorized).
		Strs("policies", decision.PolicyNames).
		Msg("policy evaluated")

	if !decision.Authorized {
		outcome = core.OutcomeDenied
		auditErr = fmt.Errorf("policy denied: %s", denyReason(*decision))
		return nil, httpError(http.StatusForbidden, auditErr)
	}

	// now resolve + mint (and roll back if partial)
	minted, err := s.resolver.Resolve(ctx, principal, req.Resources)
	if err != nil {
		auditErr = fmt.Errorf("resolution failed: %w", err)
		return nil, httpError(http.StatusInternalServerError, auditErr)
	}

	secret, err := revocationSecretFor(minted)
	if err != nil {
		s.rollback(ctx, minted)
		auditErr = fmt.Errorf("generating revocation secret: %w", err)
		return nil, httpError(http.StatusInternalServerError, auditErr)
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
		aid := xid.New().String()

		artifacts = append(artifacts, core.ArtifactAudit{
			ArtifactID:  aid,
			Provider:    m.Provider,
			Fingerprint: m.Artifact.Fingerprint,
		})
		lease.Artifacts = append(lease.Artifacts, core.LeasedArtifact{
			ArtifactID:                 aid,
			Provider:                   m.Provider,
			Realm:                      m.Realm,
			Covers:                     m.Covers,
			Fingerprint:                m.Artifact.Fingerprint,
			ExpiresAt:                  m.Artifact.ExpiresAt,
			Revocable:                  m.Revocable,
			RevocationID:               m.RevocationID,
			Metadata:                   m.Artifact.Metadata,
			RequiresTokenForRevocation: m.RequiresTokenForRevocation,
		})
		resp.Artifacts = append(resp.Artifacts, IssuedArtifact{
			ArtifactID:                 aid,
			Provider:                   m.Provider,
			Realm:                      m.Realm,
			Covers:                     m.Covers,
			Token:                      m.Artifact.Value,
			Fingerprint:                m.Artifact.Fingerprint,
			ExpiresAt:                  m.Artifact.ExpiresAt,
			Metadata:                   m.Artifact.Metadata,
			RequiresTokenForRevocation: m.RequiresTokenForRevocation,
		})
	}

	if err := s.leaseStore.SaveLease(ctx, lease); err != nil {
		s.rollback(ctx, minted)
		auditErr = fmt.Errorf("persisting lease failed: %w", err)
		return nil, httpError(http.StatusInternalServerError, auditErr)
	}

	outcome = core.OutcomeSuccess
	logger.Info().
		Str("lease_id", leaseID).
		Int("artifacts", len(lease.Artifacts)).
		Strs("policies", decision.PolicyNames).
		Bool("revocable", secret != "").
		Msg("lease.issued")
	return resp, nil
}

func (s *TokenService) RevokeLease(ctx context.Context, req RevokeRequest) (*RevokeResponse, error) {
	logger := log.Ctx(ctx)

	var (
		principal *core.Principal
		outcome   = core.OutcomeFailure
		auditErr  error
		meta      = map[string]any{}
	)
	defer func() {
		if err := s.recorder.Record(ctx, core.ActionLeaseRevoke, outcome,
			audit.WithActor(principal),
			audit.WithRevision(s.revision),
			audit.WithMetadata(meta),
			audit.WithError(auditErr),
		); err != nil {
			logger.Error().Err(err).Msg("failed to write audit log entry for lease revocation")
		}
	}()

	lease, err := s.leaseStore.FindByRevocationSecret(ctx, req.RevocationSecret)
	if errors.Is(err, core.ErrLeaseNotFound) {
		auditErr = fmt.Errorf("invalid revocation secret")
		return nil, httpError(http.StatusUnauthorized, auditErr)
	}
	if err != nil {
		auditErr = fmt.Errorf("store lookup failed: %w", err)
		return nil, httpError(http.StatusInternalServerError, auditErr)
	}

	principal = &core.Principal{ID: lease.PrincipalID, Issuer: lease.Issuer}
	meta["lease_id"] = lease.ID

	logger.UpdateContext(func(c zerolog.Context) zerolog.Context {
		return c.Str("sub", lease.PrincipalID).Str("lease_id", lease.ID)
	})

	var pending []core.LeasedArtifact
	for _, a := range lease.Artifacts {
		if a.Revocable && !a.Revoked {
			pending = append(pending, a)
		}
	}
	if len(pending) == 0 {
		outcome = core.OutcomeSuccess
		logger.Debug().Msg("lease.revoke: nothing to revoke (no active revocable artifacts)")
		return &RevokeResponse{LeaseID: lease.ID}, nil
	}

	errs := make([]error, 0, len(pending))
	revoked := make([]string, 0, len(pending))
	for _, a := range pending {
		var tok string
		if a.RequiresTokenForRevocation {
			tok = req.Tokens[a.ArtifactID]
			if tok == "" {
				errs = append(errs, fmt.Errorf("missing token for artifact %s (provider %q)", a.ArtifactID, a.Provider))
				continue
			}
		}
		if err := s.resolver.Revoke(ctx, a.Provider, a.RevocationID, tok); err != nil {
			errs = append(errs, fmt.Errorf("provider %q artifact %s: %w", a.Provider, a.ArtifactID, err))
			continue
		}
		if err := s.leaseStore.SetArtifactRevoked(ctx, lease.ID, a.ArtifactID); err != nil {
			// upstream is revoked but persistence failed
			errs = append(errs, fmt.Errorf("marking artifact %s revoked: %w", a.ArtifactID, err))
			continue
		}
		revoked = append(revoked, a.ArtifactID)
	}
	if len(errs) > 0 {
		joined := errors.Join(errs...)
		auditErr = fmt.Errorf("revocation failed: %w", joined)
		return nil, httpError(http.StatusInternalServerError, auditErr)
	}

	outcome = core.OutcomeSuccess
	meta["revoked_count"] = len(revoked)

	logger.Info().
		Int("revoked", len(revoked)).
		Int("pending", len(pending)).
		Msg("lease.revoked")
	return &RevokeResponse{
		LeaseID: lease.ID,
		Revoked: revoked,
	}, nil
}

// Explain verifies the token and evaluates policy without minting, persisting or auditing.
func (s *TokenService) Explain(ctx context.Context, req IssueRequest) (*ExplainResponse, error) {
	if len(req.Resources) == 0 {
		return nil, httpError(http.StatusBadRequest, fmt.Errorf("no resources requested"))
	}
	issuer, err := s.selectIssuer(req)
	if err != nil {
		return nil, httpError(http.StatusUnauthorized, err)
	}
	principal, err := issuer.Verify(ctx, req.Token)
	if err != nil {
		return nil, httpError(http.StatusUnauthorized, fmt.Errorf("verification faild: %w", err))
	}
	decision := s.policyManager.GetEngine().Authorize(principal, req.Resources)
	return &ExplainResponse{
		Principal: principal,
		Decision:  decision,
	}, nil
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
	cancelCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()

	logger := log.Ctx(cancelCtx)
	for _, m := range minted {
		if !m.Revocable {
			continue
		}
		if err := s.resolver.Revoke(cancelCtx, m.Provider, m.RevocationID, m.Artifact.Value); err != nil {
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
