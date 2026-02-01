package service

import (
	"context"
	"fmt"
	"net/http"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/darmiel/talmi/internal/core"
)

func (s *TokenService) ExplainTrace(ctx context.Context, req ExplainRequest) (*core.EvaluationTrace, error) {
	logger := log.Ctx(ctx)

	var principal *core.Principal
	if req.ReplayID != "" {
		logger.UpdateContext(func(c zerolog.Context) zerolog.Context {
			return c.Str("replay_id", req.ReplayID)
		})

		// fetch the audit entry to replay
		entries, err := s.auditor.Find(func(entry core.AuditEntry) bool {
			return entry.ID == req.ReplayID
		}, 1)
		if err != nil {
			return nil, httpError(http.StatusInternalServerError,
				fmt.Errorf("failed to retrieve audit log for replay: %w", err))
		}
		if len(entries) == 0 {
			return nil, httpError(http.StatusNotFound,
				fmt.Errorf("audit log entry with ID '%s' not found for replay", req.ReplayID))
		}

		principal = entries[0].Principal
		if principal == nil {
			return nil, httpError(http.StatusBadRequest,
				fmt.Errorf("no principal found in audit log for replay"))
		}

		// re-use the targets from the audit entry
		if len(req.Targets) == 0 && len(entries[0].RequestedTargets) > 0 {
			req.Targets = entries[0].RequestedTargets
		}

		logger.Debug().Str("sub", principal.ID).Msg("replaying audit log entry")
	} else {
		// "live" mode
		if req.Token == "" {
			return nil, httpError(http.StatusBadRequest,
				fmt.Errorf("token is required when not replaying an audit log"))
		}

		var issuer core.Issuer
		if req.RequestedIssuer != "" {
			// the user specified a specific issuer
			iss, ok := s.issuers.Get(req.RequestedIssuer)
			if !ok {
				logger.Warn().Str("requested_issuer", req.RequestedIssuer).Msgf("requested issuer not found")
				return nil, httpError(http.StatusBadRequest,
					fmt.Errorf("requested issuer '%s' not found", req.RequestedIssuer))
			}
			issuer = iss
			logger.Debug().Str("issuer", issuer.Name()).Msg("using explicit issuer")
		} else {
			iss, err := s.issuers.IdentifyIssuer(req.Token)
			if err != nil {
				logger.Warn().Err(err).Msgf("issuer auto-discovery failed")
				return nil, httpError(http.StatusBadRequest,
					fmt.Errorf("could not identify issuer from token: %w", err))
			}
			issuer = iss
			logger.Debug().Str("issuer", issuer.Name()).Msg("using discovered issuer")
		}

		var err error
		principal, err = issuer.Verify(ctx, req.Token)
		if err != nil {
			logger.Warn().Err(err).Str("issuer", issuer.Name()).Msgf("upstream token verification failed")
			return nil, httpError(http.StatusUnauthorized,
				fmt.Errorf("token verification failed: %w", err))
		}
	}
	logger.UpdateContext(func(c zerolog.Context) zerolog.Context {
		return c.Str("sub", principal.ID)
	})

	// run engine trace
	engine := s.policyManager.GetEngine()

	trace := engine.Trace(principal, req.Targets)
	trace.CorrelationID = req.ReplayID

	return &trace, nil
}
