# Configure rate limiting

Talmi can throttle abusive traffic before it reaches the issuance pipeline or the upstream providers. This guide turns
it on and tunes it. For the full field and cost tables, see
[Rate limiting reference](../reference/rate-limiting.md).

## The model: a token bucket with debt

Each key (an IP or a principal) gets one token bucket with a `capacity` (burst ceiling) and a
`refill_per_sec` rate.

- **Admission** happens before the work: if the balance is above zero, the request is admitted.
- **Charging** happens after the outcome is known: the cost is subtracted. The balance can go negative (debt), which
  forces the key to wait for refill before its next request is admitted. Debt is floored at `-capacity`, so one
  expensive request cannot lock a key out indefinitely.

Pricing is response-aware: a clean request costs a little, an auth failure or a heavy operation costs a lot, so abuse
throttles itself while normal traffic is barely touched. There are two layers: one bucket per client IP at the edge
(covers floods and probing) and one per verified principal on the token path (covers an authenticated-but-abusive
caller). Either being empty yields `429`.

## Before you begin

- A running Talmi server you administer. Rate limiting is off until you configure it.
- If Talmi runs behind an ingress, know your proxy CIDRs (see step 3).

## 1. Turn it on

Add a `rate_limit` block to the bootstrap file with the two profiles:

```yaml
rate_limit:
  enabled: true
  backend: memory
  ip:        { capacity: 60,  refill_per_sec: 1 }
  principal: { capacity: 120, refill_per_sec: 2 }
```

The defaults are a sane production posture: `enabled: true` alone protects the endpoint.

## 2. Choose a backend

`memory` keeps state per instance. For more than one replica, use `redis` so all replicas share one view; on a Redis
outage the limiter falls back to per-instance in-memory and never fails open:

```yaml
  backend: redis
  redis:
    addr: redis:6379
    password: env:REDIS_PASSWORD
```

## 3. Set trusted proxies behind an ingress

Behind an ingress or load balancer, the TCP peer is the proxy, not the client. List your proxy CIDRs so Talmi reads the
real client from `X-Forwarded-For`; otherwise every request looks like it came from the ingress and shares one bucket.
Add internal callers to `bypass_cidrs` to skip limiting:

```yaml
  trusted_proxies: [ "10.0.0.0/8" ]
  bypass_cidrs:    [ "10.1.2.0/24" ]
```

The default trusts nothing and uses the peer, which is correct when Talmi is the edge and cannot be spoofed.

## 4. Tune costs (optional)

Override any cell of the [cost table](../reference/rate-limiting.md#cost-table) under `costs`:

```yaml
  costs:
    issue:        { auth_error: 12 }
    task_trigger: { success: 10 }
```

## Verify

Validate the config, then hammer an endpoint with a bad token until the IP bucket drains:

```bash
talmi config vet talmi.yaml --local
for i in $(seq 1 12); do
  curl -s -o /dev/null -w "%{http_code} " -X POST localhost:8080/v2/token/issue \
    -d '{"token":"bogus","resources":[{"resource":"x:y","actions":["read"]}]}'
done; echo
```

Expect a run of `401`s then `429`s. Inspect the headers on a `429`:

```bash
curl -si -X POST localhost:8080/v2/token/issue \
  -d '{"token":"bogus","resources":[{"resource":"x:y","actions":["read"]}]}' \
  | grep -iE 'HTTP/|ratelimit-|retry-after'
```

## Troubleshooting

- **All clients share one bucket**: `trusted_proxies` is unset behind an ingress. Set it to the ingress CIDR.
- **`config vet` reports `CFG-RATELIMIT`**: a non-positive capacity/refill, a bad CIDR, a negative cost, or
  `backend: redis` without `redis.addr`.
- **Limits reset on every deploy with `memory`**: expected; use `redis` to share state across pods and restarts.

## Next steps

- Reference: [Rate limiting](../reference/rate-limiting.md).
- [Deploy to Kubernetes](deploy-kubernetes.md), [Security overview](../security/index.md).
