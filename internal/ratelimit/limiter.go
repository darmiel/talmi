package ratelimit

import (
	"context"
	"time"
)

// The two rate-limiting layers. A request draws from the IP bucket always and, once its
// identity is known, from the principal bucket too.
const (
	LayerIP        = "ip"
	LayerPrincipal = "principal"
)

// Limiter is the interface for a rate limiter that tracks budget for keys.
type Limiter interface {
	// Admit reports whether the key currently has any budget (balance > 0).
	Admit(ctx context.Context, key Key) (Decision, error)
	// Charge subtracts cost from the key's balance.
	Charge(ctx context.Context, key Key, cost int) error
}

// Profile is the capacity + refill for a layer (ip or principal).
type Profile struct {
	Capacity     int
	RefillPerSec float64
}

// Key identifies a bucket: which layer, which id and the profile that applies.
type Key struct {
	Layer   string // LayerIP or LayerPrincipal
	ID      string // the IP or issuer:subject
	Profile Profile
}

// IPKey builds a key for the per-IP layer.
func IPKey(ip string, profile Profile) Key {
	return Key{
		Layer:   LayerIP,
		ID:      ip,
		Profile: profile,
	}
}

// PrincipalKey builds a key for the per-principal layer from a verified identity.
func PrincipalKey(issuer, subject string, profile Profile) Key {
	return Key{
		Layer:   LayerPrincipal,
		ID:      issuer + ":" + subject,
		Profile: profile,
	}
}

type Decision struct {
	Allowed    bool
	RetryAfter time.Duration
	Limit      int
	Remaining  int
	Reset      time.Duration
}
