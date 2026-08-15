package resolver

import (
	"context"
	"fmt"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/darmiel/talmi/internal/core"
	"github.com/darmiel/talmi/internal/realm"
)

// Resolver selects providers and mints artifacts for authorized requests.
type Resolver struct {
	providers []core.ResourceProvider
	realms    *realm.Registry
}

// New creates a Resolver over the given provider instances and realm semantics.
// Note that the order of providers matters.
func New(providers []core.ResourceProvider, realms *realm.Registry) *Resolver {
	return &Resolver{
		providers: providers,
		realms:    realms,
	}
}

// Minted is one successfully minted artifact and what it covers
type Minted struct {
	Provider                   string
	Realm                      string
	Covers                     []core.ResourceRequest
	Artifact                   *core.TokenArtifact
	Revocable                  bool
	RevocationID               string
	RequiresTokenForRevocation bool
}

// RequestResolution is the capability-only preview of how the one request would resolve.
type RequestResolution struct {
	Resource   core.Resource         `json:"resource"`
	Actions    []core.Action         `json:"actions"`
	Realm      string                `json:"realm"`
	Chosen     string                `json:"chosen"` // provider name, or empty if none
	Reason     string                `json:"reason,omitempty"`
	Candidates []CandidateResolution `json:"candidates"`
}

// CandidateResolution is one provider's verdict for a request during preview.
type CandidateResolution struct {
	Provider string `json:"provider"`
	Covered  bool   `json:"covered"`
	Reason   string `json:"reason,omitempty"` // when not Covered: the semantics reason
}

type candidate struct {
	provider   core.ResourceProvider
	capability core.Capability
	order      int
}

type mintedRecord struct {
	provider core.ResourceProvider
	minted   Minted
}

func (r *Resolver) Resolve(
	ctx context.Context,
	principal *core.Principal,
	requests []core.ResourceRequest,
) ([]Minted, error) {
	if len(requests) == 0 {
		return nil, nil
	}

	assignments, err := r.assign(ctx, requests)
	if err != nil {
		return nil, err
	}

	log.Ctx(ctx).Debug().
		Int("requests", len(requests)).
		Int("providers", len(assignments)).
		Msg("resolver: provider assignments computed")

	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()

	var done []mintedRecord
	for _, p := range r.providers {
		assigned := assignments[p.Name()]
		if len(assigned) == 0 {
			continue
		}
		plans, err := p.Plan(ctx, assigned)
		if err != nil {
			r.rollback(cleanupCtx, done)
			return nil, fmt.Errorf("planning for provider %q: %w", p.Name(), err)
		}
		log.Ctx(ctx).Debug().
			Str("provider", p.Name()).
			Str("realm", p.Realm()).
			Int("plans", len(plans)).
			Msg("resolver: minting artifacts")
		for _, plan := range plans {
			artifact, err := p.Mint(ctx, principal, plan)
			if err != nil {
				r.rollback(cleanupCtx, done)
				return nil, fmt.Errorf("minting for provider %q: %w", p.Name(), err)
			}

			revoker, revocable := p.(core.TokenRevoker)
			requiresTokenForRevocation := false
			if revocable {
				requiresTokenForRevocation = revoker.RequiresTokenForRevocation()
			}

			done = append(done, mintedRecord{
				provider: p,
				minted: Minted{
					Provider:                   p.Name(),
					Realm:                      p.Realm(),
					Covers:                     plan.Covers,
					Artifact:                   artifact,
					Revocable:                  revocable,
					RevocationID:               artifact.RevocationID(),
					RequiresTokenForRevocation: requiresTokenForRevocation,
				},
			})
		}
	}

	result := make([]Minted, len(done))
	for i, record := range done {
		result[i] = record.minted
	}
	return result, nil
}

func (r *Resolver) assign(
	ctx context.Context,
	requests []core.ResourceRequest,
) (map[string][]core.ResourceRequest, error) {
	byRealm, err := r.candidatesByRealm(ctx, requests)
	if err != nil {
		return nil, err
	}
	assignments := make(map[string][]core.ResourceRequest)
	for _, request := range requests {
		realmName, ok := request.Resource.Realm()
		if !ok {
			return nil, fmt.Errorf("resource %q has no realm prefix", request.Resource)
		}
		semantics, ok := r.realms.Get(realmName)
		if !ok {
			return nil, fmt.Errorf("unknown realm %q for resource %q", realmName, request.Resource)
		}
		chosen, ok := selectProvider(semantics, byRealm[realmName], request)
		if !ok {
			return nil, fmt.Errorf("no provider can serve resource %q with actions %v",
				request.Resource, request.Actions)
		}
		log.Ctx(ctx).Debug().
			Str("resource", string(request.Resource)).
			Interface("actions", request.Actions).
			Str("realm", realmName).
			Str("provider", chosen).
			Msg("resolver: selected least-privileged provider")
		assignments[chosen] = append(assignments[chosen], request)
	}
	return assignments, nil
}

func (r *Resolver) PlanOnly(ctx context.Context, requests []core.ResourceRequest) ([]core.MintPlan, error) {
	if len(requests) == 0 {
		return nil, nil
	}
	assignments, err := r.assign(ctx, requests)
	if err != nil {
		return nil, err
	}
	var plans []core.MintPlan
	for _, p := range r.providers {
		assigned := assignments[p.Name()]
		if len(assigned) == 0 {
			continue
		}
		ps, err := p.Plan(ctx, assigned)
		if err != nil {
			return nil, fmt.Errorf("planning for provider %q: %w", p.Name(), err)
		}
		plans = append(plans, ps...)
	}
	return plans, nil
}

func (r *Resolver) Preview(ctx context.Context, requests []core.ResourceRequest) ([]RequestResolution, error) {
	if len(requests) == 0 {
		return nil, nil
	}
	byRealm, err := r.candidatesByRealm(ctx, requests)
	if err != nil {
		return nil, err
	}
	out := make([]RequestResolution, 0, len(requests))
	for _, req := range requests {
		rr := RequestResolution{
			Resource: req.Resource,
			Actions:  req.Actions,
		}
		realmName, ok := req.Resource.Realm()
		if !ok {
			rr.Reason = "resource has no realm prefix"
			out = append(out, rr)
			continue
		}
		rr.Realm = realmName
		semantics, ok := r.realms.Get(realmName)
		if !ok {
			rr.Reason = fmt.Sprintf("unknown realm %q", realmName)
			out = append(out, rr)
			continue
		}
		cands := byRealm[realmName]
		for _, c := range cands {
			allow := core.Allow{
				Resources: c.capability.Resources,
				Actions:   c.capability.MaxActions,
			}
			covered, reason := semantics.Covers([]core.Allow{allow}, req)
			rr.Candidates = append(rr.Candidates, CandidateResolution{
				Provider: c.provider.Name(),
				Covered:  covered,
				Reason:   reason,
			})
		}
		if chosen, ok := selectProvider(semantics, cands, req); ok {
			rr.Chosen = chosen
		} else {
			rr.Reason = fmt.Sprintf("no provider can serve resource %q with actions %v",
				req.Resource, req.Actions)
		}
		out = append(out, rr)
	}
	return out, nil
}

// Revoke revokes a single artifact through its minting provider.
func (r *Resolver) Revoke(ctx context.Context, providerName, revocationID, tokenValue string) error {
	for _, p := range r.providers {
		if p.Name() != providerName {
			continue
		}
		revoker, ok := p.(core.TokenRevoker)
		if !ok {
			return fmt.Errorf("provider %q does not support revocation", providerName)
		}
		return revoker.Revoke(ctx, revocationID, tokenValue)
	}
	return fmt.Errorf("provider %q not found", providerName)
}

func (r *Resolver) candidatesByRealm(
	ctx context.Context,
	requests []core.ResourceRequest,
) (map[string][]candidate, error) {
	wanted := make(map[string]struct{})
	for _, request := range requests {
		if realmName, ok := request.Resource.Realm(); ok {
			wanted[realmName] = struct{}{}
		}
	}

	byRealm := make(map[string][]candidate)
	for i, provider := range r.providers {
		if _, ok := wanted[provider.Realm()]; !ok {
			continue
		}
		capabilities, err := provider.Capabilities(ctx)
		if err != nil {
			return nil, fmt.Errorf("fetching capabilities for provider %q: %w", provider.Name(), err)
		}
		byRealm[provider.Realm()] = append(byRealm[provider.Realm()], candidate{
			provider:   provider,
			capability: capabilities,
			order:      i,
		})
	}

	return byRealm, nil
}

// selectProvider picks the least-privileged candidate that can serve request.
func selectProvider(semantics realm.Semantics, candidates []candidate, request core.ResourceRequest) (string, bool) {
	chosen := ""
	var bestScore, bestBreadth, bestOrder int
	for _, c := range candidates {
		allow := core.Allow{Resources: c.capability.Resources, Actions: c.capability.MaxActions}
		if covered, _ := semantics.Covers([]core.Allow{allow}, request); !covered {
			continue
		}
		score := privilegeScore(semantics, c.capability.MaxActions, request.Actions)
		breadth := len(c.capability.Resources)
		if chosen == "" || rankLess(score, breadth, c.order, bestScore, bestBreadth, bestOrder) {
			chosen, bestScore, bestBreadth, bestOrder = c.provider.Name(), score, breadth, c.order
		}
	}
	return chosen, chosen != ""
}

// privilegeScore is the summed "excess" of a provider's ceiling
func privilegeScore(semantics realm.Semantics, capActions, reqActions []core.Action) int {
	total := 0
	for _, ra := range reqActions {
		best := -1
		for _, ca := range capActions {
			cmp, err := semantics.CompareLevel(ca, ra)
			if err != nil || cmp < 0 {
				continue // different permission or ceiling below request
			}
			if best == -1 || cmp < best {
				best = cmp
			}
		}
		if best > 0 {
			total += best
		}
	}
	return total
}

func rankLess(score, breadth, order, bScore, bBreadth, bOrder int) bool {
	switch {
	case score != bScore:
		return score < bScore
	case breadth != bBreadth:
		return breadth < bBreadth
	default:
		return order < bOrder
	}
}

func (r *Resolver) rollback(ctx context.Context, records []mintedRecord) {
	logger := log.Ctx(ctx)
	if len(records) == 0 {
		return
	}
	logger.Warn().
		Int("artifacts", len(records)).
		Msg("resolver: rolling back minted artifacts after failure")
	for _, rec := range records {
		revoker, ok := rec.provider.(core.TokenRevoker)
		if !ok {
			continue
		}
		revID := rec.minted.Artifact.RevocationID()
		if revID == "" {
			continue
		}
		if err := revoker.Revoke(ctx, revID, rec.minted.Artifact.Value); err != nil {
			logger.Error().Err(err).
				Str("provider", rec.minted.Provider).
				Msg("rollback: failed to revoke artifact after mint failure")
		}
	}
}
