package ratelimit

import (
	"context"
	"time"
)

// Limiter is the interface for a rate limiter that tracks budget for keys.
type Limiter interface {
	// Admit reports whether the key currently has any budget (balance > 0).
	Admit(ctx context.Context, key Key) (Decision, error)
	// Charge subtracts cost from the key's balance.
	Charge(ctx context.Context, key Key, cost int) error
}

// Profile is the capacity + refill for a layer (ip or core.Principal).
type Profile struct {
	Capacity     int
	RefillPerSec float64
}

// Key identifies a bucket, which layer, which id and the profile that applies.
type Key struct {
	Layer   string // "ip" or "principal"
	ID      string // the IP or issuer:subject
	Profile Profile
}

type Decision struct {
	Allowed    bool
	RetryAfter time.Duration
	Limit      int
	Remaining  int
	Reset      time.Duration
}
