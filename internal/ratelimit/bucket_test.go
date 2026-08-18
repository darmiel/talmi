package ratelimit

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// fakeClock is an injectable clock for deterministic bucket refill tests.
type fakeClock struct {
	t time.Time
}

func (c *fakeClock) now() time.Time { return c.t }

func TestBucketAdmitAndDebt(t *testing.T) {
	t.Parallel()
	is := assert.New(t)
	clk := &fakeClock{t: time.Unix(0, 0)}
	b := newBucket(10, 1, clk.now) // capacity 10, 1 token/sec

	is.True(b.admit(), "full bucket admits")
	b.charge(10) // now at 0
	is.False(b.admit(), "empty bucket rejects")

	b.charge(5) // debt -5
	d := b.snapshot()
	is.Equal(0, d.Remaining, "remaining never negative")
	is.InDelta(5.0, d.RetryAfter.Seconds(), 0.01, "wait to positive = 5s at 1/s (-5 balance)")

	clk.t = clk.t.Add(6 * time.Second)
	is.True(b.admit(), "refills back to positive")
}

func TestBucketDebtFloor(t *testing.T) {
	t.Parallel()
	clk := &fakeClock{t: time.Unix(0, 0)}
	b := newBucket(10, 1, clk.now)
	b.charge(1000) // huge
	assert.InDelta(t, 10.0, b.snapshot().RetryAfter.Seconds(), 0.01,
		"debt floored at -capacity, so wait to positive <= capacity/refill")
}
