package ratelimit

import "context"

var _ Limiter = (*NopLimiter)(nil)

type NopLimiter struct{}

func NewNopLimiter() *NopLimiter {
	return &NopLimiter{}
}

func (l *NopLimiter) Admit(ctx context.Context, key Key) (Decision, error) {
	return Decision{
		Allowed: true,
	}, nil
}

func (l *NopLimiter) Charge(ctx context.Context, key Key, cost int) error {
	return nil
}
