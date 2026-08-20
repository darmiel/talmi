package ratelimit

import "context"

var _ Limiter = (*NopLimiter)(nil)

// NopLimiter admits everything and charges nothing.
type NopLimiter struct{}

func NewNopLimiter() *NopLimiter {
	return &NopLimiter{}
}

func (*NopLimiter) Admit(_ context.Context, _ Key) (Decision, error) {
	return Decision{
		Allowed: true,
	}, nil
}

func (*NopLimiter) Charge(_ context.Context, _ Key, _ int) error {
	return nil
}
