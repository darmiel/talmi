package middleware

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/darmiel/talmi/internal/ratelimit"
)

// fixedStatusHandler writes a constant status code.
func fixedStatusHandler(status int) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
	})
}

func do(h http.Handler, method, path, remote string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	req.RemoteAddr = remote
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestRateLimitMiddlewareBurst(t *testing.T) {
	t.Parallel()
	mem := ratelimit.NewMemoryLimiter(ratelimit.MemoryOptions{})
	defer mem.Close()

	mw := RateLimitMiddleware(RateLimitConfig{
		Limiter:     mem,
		Costs:       ratelimit.DefaultCosts(),
		IPProfile:   ratelimit.Profile{Capacity: 15, RefillPerSec: 1},
		CategoryFor: func(*http.Request) ratelimit.Category { return ratelimit.CategoryIssue },
	})
	// every request fails auth (cost 10 for issue), so the 15-token bucket drains in 2.
	h := mw(fixedStatusHandler(http.StatusUnauthorized))

	got401 := 0
	var throttled *httptest.ResponseRecorder
	for range 5 {
		rec := do(h, http.MethodPost, "/v2/token/issue", "203.0.113.5:1111")
		if rec.Code == http.StatusTooManyRequests {
			throttled = rec
			break
		}
		require.Equal(t, http.StatusUnauthorized, rec.Code)
		got401++
	}

	require.NotNil(t, throttled, "an auth-failing burst must eventually be throttled")
	assert.Equal(t, 2, got401, "cost-10 failures drain a 15-token bucket after 2 requests")

	// 429 carries Retry-After and the RateLimit-* draft headers.
	assert.NotEmpty(t, throttled.Header().Get("Retry-After"))
	ra, err := strconv.Atoi(throttled.Header().Get("Retry-After"))
	require.NoError(t, err)
	assert.Positive(t, ra, "debt should push Retry-After above zero")
	assert.Equal(t, "15", throttled.Header().Get("RateLimit-Limit"))
	assert.Equal(t, "0", throttled.Header().Get("RateLimit-Remaining"))
	assert.NotEmpty(t, throttled.Header().Get("RateLimit-Reset"))
}

func TestRateLimitMiddlewareCostAware(t *testing.T) {
	t.Parallel()

	admittedBefore429 := func(status int) int {
		mem := ratelimit.NewMemoryLimiter(ratelimit.MemoryOptions{})
		defer mem.Close()
		mw := RateLimitMiddleware(RateLimitConfig{
			Limiter:     mem,
			Costs:       ratelimit.DefaultCosts(),
			IPProfile:   ratelimit.Profile{Capacity: 30, RefillPerSec: 0},
			CategoryFor: func(*http.Request) ratelimit.Category { return ratelimit.CategoryIssue },
		})
		h := mw(fixedStatusHandler(status))
		admitted := 0
		for range 40 {
			rec := do(h, http.MethodPost, "/v2/token/issue", "198.51.100.7:2222")
			if rec.Code == http.StatusTooManyRequests {
				break
			}
			admitted++
		}
		return admitted
	}

	success := admittedBefore429(http.StatusOK)           // cost 1
	failing := admittedBefore429(http.StatusUnauthorized) // cost 10
	assert.Greater(t, success, failing, "expensive auth failures throttle faster than cheap successes")
}

func TestRateLimitMiddlewareExemptions(t *testing.T) {
	t.Parallel()

	t.Run("exempt path is never throttled", func(t *testing.T) {
		t.Parallel()
		mem := ratelimit.NewMemoryLimiter(ratelimit.MemoryOptions{})
		defer mem.Close()
		mw := RateLimitMiddleware(RateLimitConfig{
			Limiter:     mem,
			Costs:       ratelimit.DefaultCosts(),
			IPProfile:   ratelimit.Profile{Capacity: 1, RefillPerSec: 0},
			CategoryFor: func(*http.Request) ratelimit.Category { return ratelimit.CategoryIssue },
			Exempt:      func(r *http.Request) bool { return r.URL.Path == "/healthz" },
		})
		h := mw(fixedStatusHandler(http.StatusOK))
		for range 10 {
			rec := do(h, http.MethodGet, "/healthz", "203.0.113.9:3333")
			require.Equal(t, http.StatusOK, rec.Code, "/healthz must never be throttled")
		}
	})

	t.Run("bypass cidr peer is never throttled", func(t *testing.T) {
		t.Parallel()
		mem := ratelimit.NewMemoryLimiter(ratelimit.MemoryOptions{})
		defer mem.Close()
		mw := RateLimitMiddleware(RateLimitConfig{
			Limiter:     mem,
			Costs:       ratelimit.DefaultCosts(),
			IPProfile:   ratelimit.Profile{Capacity: 1, RefillPerSec: 0},
			Bypass:      []netip.Prefix{netip.MustParsePrefix("10.9.9.0/24")},
			CategoryFor: func(*http.Request) ratelimit.Category { return ratelimit.CategoryIssue },
		})
		h := mw(fixedStatusHandler(http.StatusOK))
		for range 10 {
			rec := do(h, http.MethodPost, "/v2/token/issue", "10.9.9.9:4444")
			require.Equal(t, http.StatusOK, rec.Code, "bypass CIDR peers skip limiting")
		}
	})
}
