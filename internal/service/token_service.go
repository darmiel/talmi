package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/darmiel/talmi/internal/core"
	"github.com/darmiel/talmi/internal/engine"
	"github.com/darmiel/talmi/internal/issuers"
)

// TokenService is the main service that handles the minting process
type TokenService struct {
	issuers       *issuers.Registry
	providers     map[string]core.Provider
	policyManager *engine.PolicyManager
	auditor       core.Auditor
	tokenStore    core.TokenStore
}

func NewTokenService(
	issuers *issuers.Registry,
	providers map[string]core.Provider,
	policyManager *engine.PolicyManager,
	auditor core.Auditor,
	tokenStore core.TokenStore,
) *TokenService {
	return &TokenService{
		issuers:       issuers,
		providers:     providers,
		policyManager: policyManager,
		auditor:       auditor,
		tokenStore:    tokenStore,
	}
}

func (s *TokenService) IssueToken(ctx context.Context, req IssueRequest) (*IssueResponse, error) {
	logger := log.Ctx(ctx)
	reqID, _ := ctx.Value("correlation_id").(string)

	auditEntry := core.AuditEntry{
		ID:                reqID,
		Time:              time.Now(),
		Action:            "token.issue",
		RequestedIssuer:   req.RequestedIssuer,
		RequestedProvider: req.RequestedProvider,
	}
	defer func() {
		if err := s.auditor.Log(auditEntry); err != nil {
			logger.Error().Err(err).Msg("failed to write audit log entry for token issuance")
		}
	}()

	// first we need to identify the issuer that we use to create the principal
	var issuer core.Issuer
	if req.RequestedIssuer != "" {
		// TODO(future): check if we should allow this in the future, if there's an issuer that accepts too many token types a user might be able to abuse that
		var ok bool
		if issuer, ok = s.issuers.Get(req.RequestedIssuer); !ok {
			auditEntry.Error = "requested issuer not found"
			auditEntry.Stacktrace = fmt.Sprintf("cannot find '%s' in issuers", req.RequestedIssuer)
			return nil, httpError(http.StatusBadRequest,
				fmt.Errorf("requested issuer '%s' not found", req.RequestedIssuer))
		}
		logger.Debug().Str("issuer", issuer.Name()).Msg("using explicit issuer")
	} else {
		var err error
		if issuer, err = s.issuers.IdentifyIssuer(req.Token); err != nil {
			auditEntry.Error = "issuer auto-discovery failed"
			auditEntry.Stacktrace = err.Error()
			return nil, httpError(http.StatusUnauthorized,
				fmt.Errorf("issuer auto-discovery failed: %w", err))
		}
		logger.Debug().Str("issuer", issuer.Name()).Msg("using discovered issuer")
	}

	principal, err := issuer.Verify(ctx, req.Token)
	if err != nil {
		auditEntry.Error = "verification failed"
		auditEntry.Stacktrace = err.Error()
		return nil, httpError(http.StatusUnauthorized,
			fmt.Errorf("verification failed: %w", err))
	}
	auditEntry.Principal = principal

	logger.UpdateContext(func(c zerolog.Context) zerolog.Context {
		return c.Str("sub", principal.ID)
	})

	// now that we have verified the principal, we can continue with evaluating the grant
	rule, err := s.policyManager.GetEngine().Evaluate(principal, req.RequestedProvider) // TODO(future): see above
	if err != nil {
		auditEntry.Success = false
		auditEntry.Stacktrace = err.Error()

		if errors.Is(err, engine.ErrNoRuleMatch) {
			auditEntry.Error = "policy denied"
			return nil, httpError(http.StatusUnauthorized,
				fmt.Errorf("policy denied: %w", err))
		}

		auditEntry.Error = "policy engine error"
		return nil, httpError(http.StatusInternalServerError,
			fmt.Errorf("policy engine error: %w", err))
	}
	auditEntry.PolicyName = rule.Name

	grant := rule.Grant

	// now find the corresponding provider used to mint the token
	baseProvider, ok := s.providers[grant.Provider]
	if !ok {
		auditEntry.Error = "provider configuration error"
		auditEntry.Stacktrace = fmt.Sprintf("cannot find '%s' in providers", grant.Provider)
		return nil, httpError(http.StatusInternalServerError,
			fmt.Errorf("provider '%s' configured in rule but not found in registry", grant.Provider))
	}
	auditEntry.Provider = baseProvider.Name()

	minter, ok := baseProvider.(core.TokenMinter)
	if !ok {
		auditEntry.Error = "minting not supported"
		return nil, httpError(http.StatusExpectationFailed,
			fmt.Errorf("provider '%s' does not support minting", grant.Provider))
	}

	effectiveGrant := grant

	// permission downscoping
	if len(req.RequestedPermissions) > 0 {
		downscoper, ok := baseProvider.(core.PermissionDownscoper)
		if !ok {
			// we should fail hard here because the requestor wants less access, but we cannot guarantee it
			auditEntry.Error = "downscoping requested but not supported"
			return nil, httpError(http.StatusBadRequest,
				fmt.Errorf("provider '%s' does not support downscoping", grant.Provider))
		}

		effectivePermissions, err := downscoper.Downscope(grant.Permissions, req.RequestedPermissions)
		if err != nil {
			auditEntry.Error = "downscoping failed"
			auditEntry.Stacktrace = err.Error()
			return nil, httpError(http.StatusBadRequest, fmt.Errorf("downscoping failed: %w", err))
		}

		effectiveGrant.Permissions = effectivePermissions
	}

	// finally, we can mint the token! :)
	artifact, err := minter.Mint(ctx, principal, effectiveGrant)
	if err != nil {
		auditEntry.Error = "minting failed"
		auditEntry.Stacktrace = err.Error()
		return nil, httpError(http.StatusInternalServerError,
			fmt.Errorf("minting failed: %w", err))
	}

	auditEntry.Success = true
	auditEntry.Metadata = artifact.Metadata
	auditEntry.TokenFingerprint = artifact.Fingerprint

	// token revocation
	revocationToken := ""
	revocationID := artifact.RevocationID() // might be empty depending on the provider
	isRevocable := false
	if _, ok := baseProvider.(core.TokenRevoker); ok {
		rawToken, err := GenerateRandomString(32)
		if err != nil {
			return nil, fmt.Errorf("crypto error: %w", err)
		}
		revocationToken = rawToken
		artifact.RevocationToken = revocationToken
		isRevocable = true
	}

	meta := core.TokenMetadata{
		CorrelationID:   reqID,
		PrincipalID:     principal.ID,
		Provider:        baseProvider.Name(),
		PolicyName:      rule.Name,
		IssuedAt:        time.Now(),
		ExpiresAt:       artifact.ExpiresAt,
		Revocable:       isRevocable,
		RevocationToken: revocationToken,
		RevocationID:    revocationID,
		Metadata:        artifact.Metadata,
	}
	if err := s.tokenStore.Save(ctx, meta); err != nil {
		logger.Error().Err(err).Msg("failed to save token metadata")
		// note that we don't fail here, this is something we might have to think about in the future
		// when we have to think about token revocation
	}

	return &IssueResponse{
		Artifact:  artifact,
		Principal: principal,
		Rule:      rule,
	}, nil
}

func (s *TokenService) RevokeToken(ctx context.Context, tokenVal, revocationToken string) (*core.TokenMetadata, error) {
	logger := log.Ctx(ctx)
	reqID, _ := ctx.Value("correlation_id").(string)

	auditEntry := core.AuditEntry{
		ID:     reqID,
		Time:   time.Now(),
		Action: "token.revoke",
	}
	defer func() {
		if err := s.auditor.Log(auditEntry); err != nil {
			logger.Error().Err(err).Msg("failed to write audit log entry for token revocation")
		}
	}()

	meta, err := s.tokenStore.FindByRevocationToken(ctx, revocationToken)
	if err != nil {
		auditEntry.Error = "invalid auth token"
		auditEntry.Stacktrace = err.Error()
		return nil, httpError(http.StatusUnauthorized, fmt.Errorf("invalid auth token"))
	}
	if meta.Revoked {
		auditEntry.Error = "already revoked"
		return nil, httpError(http.StatusGone, fmt.Errorf("already revoked"))
	}

	baseProvider, ok := s.providers[meta.Provider]
	if !ok {
		auditEntry.Error = "provider missing"
		auditEntry.Stacktrace = fmt.Sprintf("cannot find provider '%s'", meta.Provider)
		return nil, httpError(http.StatusInternalServerError, fmt.Errorf("provider missing"))
	}
	revoker, ok := baseProvider.(core.TokenRevoker)
	if !ok {
		auditEntry.Error = "provider not revoker"
		auditEntry.Stacktrace = fmt.Sprintf("provider '%s' is not a core.TokenRevoker", meta.Provider)
		return nil, httpError(http.StatusInternalServerError, fmt.Errorf("provider no longer supports revocation"))
	}

	// actually perform revocation of token
	if err := revoker.Revoke(ctx, meta.RevocationID, tokenVal); err != nil {
		auditEntry.Error = "revoking failed"
		auditEntry.Stacktrace = err.Error()
		return nil, httpError(http.StatusInternalServerError, fmt.Errorf("revocation failed: %w", err))
	}

	// mark as revoked in database
	if err := s.tokenStore.SetRevoked(ctx, meta.CorrelationID); err != nil {
		logger.Error().Err(err).Msg("failed to mark token revoked in store")
	}

	auditEntry.Success = true
	return meta, nil
}

func GenerateRandomString(bytes int) (string, error) {
	b := make([]byte, bytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
