package ratelimit

import (
	"context"
	"math"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	redisKeyPrefix = "talmi:ratelimit:"
	redsDefaultTTL = time.Hour
)

// admitScript refills lazily then reports the balance (non-consuming). Balance is in milli-tokens.
// KEYS[1]=hash key; ARGV[1]=capacity_milli, ARGV[2]=refill_per_sec, ARGV[3]=ttl_ms.
var admitScript = redis.NewScript(`
local cap = tonumber(ARGV[1])
local refill = tonumber(ARGV[2])
local ttl = tonumber(ARGV[3])
local t = redis.call('TIME')
local now_ms = tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)
local bal = redis.call('HGET', KEYS[1], 'b')
local ts
if bal == false then
  bal = cap
  ts = now_ms
else
  bal = tonumber(bal)
  ts = tonumber(redis.call('HGET', KEYS[1], 't'))
end
local elapsed = now_ms - ts
if elapsed > 0 and refill > 0 then
  bal = math.min(cap, bal + math.floor(refill * elapsed))
end
redis.call('HSET', KEYS[1], 'b', bal, 't', now_ms)
if ttl > 0 then redis.call('PEXPIRE', KEYS[1], ttl) end
return bal
`)

// chargeScript refills lazily then subtracts cost, flooring debt at -capacity.
// ARGV[4]=cost_milli.
var chargeScript = redis.NewScript(`
local cap = tonumber(ARGV[1])
local refill = tonumber(ARGV[2])
local ttl = tonumber(ARGV[3])
local cost = tonumber(ARGV[4])
local t = redis.call('TIME')
local now_ms = tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)
local bal = redis.call('HGET', KEYS[1], 'b')
local ts
if bal == false then
  bal = cap
  ts = now_ms
else
  bal = tonumber(bal)
  ts = tonumber(redis.call('HGET', KEYS[1], 't'))
end
local elapsed = now_ms - ts
if elapsed > 0 and refill > 0 then
  bal = math.min(cap, bal + math.floor(refill * elapsed))
end
bal = bal - cost
if bal < -cap then bal = -cap end
redis.call('HSET', KEYS[1], 'b', bal, 't', now_ms)
if ttl > 0 then redis.call('PEXPIRE', KEYS[1], ttl) end
return bal
`)

var _ Limiter = (*RedisLimiter)(nil)

// RedisLimiter is a shared limiter backed by an atomic Lua token bucket.
type RedisLimiter struct {
	rc  redis.Scripter
	ttl time.Duration
}

func NewRedisLimiter(rc redis.Scripter) *RedisLimiter {
	return &RedisLimiter{
		rc:  rc,
		ttl: redsDefaultTTL,
	}
}

func redisKey(key Key) string {
	return redisKeyPrefix + key.Layer + ":" + key.ID
}

func (r *RedisLimiter) Admit(ctx context.Context, key Key) (Decision, error) {
	balMilli, err := admitScript.Run(ctx, r.rc, []string{redisKey(key)},
		key.Profile.Capacity*1000, key.Profile.RefillPerSec, r.ttl.Milliseconds()).Int64()
	if err != nil {
		return Decision{}, err
	}
	return decisionFromMilli(balMilli, key.Profile), nil
}

func (r *RedisLimiter) Charge(ctx context.Context, key Key, cost int) error {
	return chargeScript.Run(ctx, r.rc, []string{redisKey(key)},
		key.Profile.Capacity*1000, key.Profile.RefillPerSec, r.ttl.Milliseconds(), cost*1000).Err()
}

func decisionFromMilli(balMilli int64, profile Profile) Decision {
	bal := float64(balMilli) / 1000
	capacity := float64(profile.Capacity)
	remaining := 0
	if bal > 0 {
		remaining = int(math.Floor(bal))
	}
	var retryAfter, reset time.Duration
	if bal <= 0 && profile.RefillPerSec > 0 {
		retryAfter = time.Duration((-bal / profile.RefillPerSec) * float64(time.Second))
	}
	if profile.RefillPerSec > 0 && bal < capacity {
		reset = time.Duration(((capacity - bal) / profile.RefillPerSec) * float64(time.Second))
	}
	return Decision{
		Allowed:    bal > 0,
		RetryAfter: retryAfter,
		Limit:      profile.Capacity,
		Remaining:  remaining,
		Reset:      reset,
	}
}
