package middleware

import (
	"math"
	"net/http"
	"net/netip"
	"strconv"

	"github.com/rs/zerolog/log"

	"github.com/darmiel/talmi/internal/api/presenter"
	"github.com/darmiel/talmi/internal/correlation"
	"github.com/darmiel/talmi/internal/ratelimit"
)

type RateLimitConfig struct {
	Limiter     ratelimit.Limiter
	Costs       ratelimit.CostTable
	IPProfile   ratelimit.Profile
	Trusted     []netip.Prefix // proxies we trust the XFF
	Bypass      []netip.Prefix // client IPs that skip limiting entirely
	CategoryFor func(*http.Request) ratelimit.Category
	Exempt      func(*http.Request) bool // always skip limiting for this request, e.g. healthz
}

func RateLimitMiddleware(cfg RateLimitConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if cfg.Exempt != nil && cfg.Exempt(r) {
				next.ServeHTTP(w, r)
				return
			}

			ip := ratelimit.ClientIP(r, cfg.Trusted)
			if addr, err := netip.ParseAddr(ip); err == nil && ratelimit.InPrefixes(addr, cfg.Bypass) {
				next.ServeHTTP(w, r)
				return
			}

			key := ratelimit.IPKey(ip, cfg.IPProfile)
			ctx := r.Context()

			d, err := cfg.Limiter.Admit(ctx, key)
			if err != nil {
				// if the limiter failed something is very wrong, but we don't want to block the request
				log.Ctx(ctx).Error().Err(err).Msg("ratelimit: admit failed, allowing request")
				next.ServeHTTP(w, r)
				return
			}

			setRateLimitHeaders(w, d)
			if !d.Allowed {
				retryAfter := max(1, int(math.Ceil(d.RetryAfter.Seconds())))
				w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
				presenter.JSON(w, r, rateLimitResponse{
					Error:         "rate limit exceeded",
					CorrelationID: correlation.From(ctx),
				}, http.StatusTooManyRequests)
				return
			}

			ww := &statusWriter{ResponseWriter: w, statusCode: http.StatusOK}
			next.ServeHTTP(ww, r)

			cat := ratelimit.CategoryDefault
			if cfg.CategoryFor != nil {
				cat = cfg.CategoryFor(r)
			}
			cost := cfg.Costs.Cost(cat, ratelimit.ClassFromStatus(ww.statusCode))
			if err := cfg.Limiter.Charge(ctx, key, cost); err != nil {
				log.Ctx(ctx).Error().Err(err).Msg("ratelimit: charge failed")
			}
		})
	}
}

type rateLimitResponse struct {
	Error         string `json:"error"`
	CorrelationID string `json:"correlation_id"`
}

func setRateLimitHeaders(w http.ResponseWriter, d ratelimit.Decision) {
	w.Header().Set("RateLimit-Limit", strconv.Itoa(d.Limit))
	w.Header().Set("RateLimit-Remaining", strconv.Itoa(d.Remaining))
	w.Header().Set("RateLimit-Reset", strconv.Itoa(int(math.Ceil(d.Reset.Seconds()))))
}
