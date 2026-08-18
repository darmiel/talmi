package ratelimit

import (
	"context"
	"log/slog"
	"sync/atomic"
)

var _ Limiter = (*Fallback)(nil)

type Fallback struct {
	primary Limiter
	local   Limiter
	log     *slog.Logger
	count   atomic.Int64
}

func NewFallback(primary, local Limiter) *Fallback {
	return &Fallback{
		primary: primary,
		local:   local,
	}
}

func (f *Fallback) WithLogger(l *slog.Logger) *Fallback {
	f.log = l
	return f
}

func (f *Fallback) Admit(ctx context.Context, key Key) (Decision, error) {
	d, err := f.primary.Admit(ctx, key)
	if err != nil {
		f.onError("admit", key, err)
		return f.local.Admit(ctx, key)
	}
	return d, nil
}

func (f *Fallback) Charge(ctx context.Context, key Key, cost int) error {
	err := f.primary.Charge(ctx, key, cost)
	if err != nil {
		f.onError("charge", key, err)
		return f.local.Charge(ctx, key, cost)
	}
	return nil
}

func (f *Fallback) FallbackCount() int64 {
	return f.count.Load()
}

func (f *Fallback) onError(op string, key Key, err error) {
	f.count.Add(1)
	if f.log != nil {
		f.log.Warn("rate limiter backend fallback",
			"op", op,
			"layer", key.Layer,
			"error", err)
	}
}
