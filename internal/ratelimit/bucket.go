package ratelimit

import (
	"math"
	"time"
)

// bucket is a single token bucket with debt. Balance may go negative to -capacity, which forces a wait
// before the key is admitted again.
//
// NOT SAFE FOR CONCURRENT USE.
type bucket struct {
	capacity float64
	refill   float64 // tokens per second, 0 = no refill
	balance  float64
	last     time.Time
	now      func() time.Time
}

func newBucket(capacity, refillPerSec float64, now func() time.Time) *bucket {
	return &bucket{
		capacity: capacity,
		refill:   refillPerSec,
		balance:  capacity,
		last:     now(),
		now:      now,
	}
}

func (b *bucket) refillNow() {
	t := b.now()
	if b.refill > 0 {
		elapsed := t.Sub(b.last).Seconds()
		if elapsed > 0 {
			b.balance = math.Min(b.capacity, b.balance+elapsed*b.refill)
		}
	}
	b.last = t
}

// admit reports whether the key has any budget left.
func (b *bucket) admit() bool {
	b.refillNow()
	return b.balance > 0
}

func (b *bucket) charge(cost float64) {
	b.refillNow()
	b.balance -= cost
	if b.balance < -b.capacity {
		b.balance = -b.capacity
	}
}

func (b *bucket) snapshot() Decision {
	b.refillNow()
	return decisionFor(b.balance, b.capacity, b.refill)
}

// decisionFor derives the response fields from a raw balance. RetryAfter is the time until the
// balance is positive again (time-to-retry); Reset is the time until the bucket is full. Both are
// zero when the bucket does not refill.
func decisionFor(balance, capacity, refillPerSec float64) Decision {
	remaining := 0
	if balance > 0 {
		remaining = int(math.Floor(balance))
	}

	var retryAfter, reset time.Duration
	if refillPerSec > 0 {
		if balance <= 0 {
			retryAfter = time.Duration((-balance / refillPerSec) * float64(time.Second))
		}
		if balance < capacity {
			reset = time.Duration(((capacity - balance) / refillPerSec) * float64(time.Second))
		}
	}

	return Decision{
		Allowed:    balance > 0,
		RetryAfter: retryAfter,
		Limit:      int(capacity),
		Remaining:  remaining,
		Reset:      reset,
	}
}
