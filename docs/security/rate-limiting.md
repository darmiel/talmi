# Rate limiting

Talmi may be used in a public network, so it can throttle abusive traffic before it reaches the issuance pipeline or the
upstream providers. Limiting is **response-aware**: a clean request costs a little quota, while an auth failure or a
heavy operation costs a lot.

Rate limiting is off until you configure it. A public deployment should turn it on; `config vet`
warns when the section is present but disabled.

## The model: a token bucket with debt

Each key (an IP or a principal) gets one token bucket with a `capacity` (the burst ceiling) and a
`refill_per_sec` rate. The bucket refills continuously up to capacity.

- **Admission** happens before the work: if the balance is above zero, the request is admitted.
- **Charging** happens after the outcome is known: the request's cost is subtracted. The balance can go **negative**
  (debt), which forces the key to wait for refill before its next request is admitted. Debt is floored at `-capacity`,
  so a single expensive request can never lock a key out for an unbounded time.

A request is admitted while any budget remains, because the cost is not known until the request has been handled. The
post-hoc charge is what creates the back-pressure: one expensive auth failure against a small bucket forces a real wait
before the next attempt.

## Two layers

- **Per IP**, at the edge. Keyed by the client address, applied before the handler runs and charged from the response
  status. This is the only layer that sees unauthenticated traffic (probing, floods).
- **Per principal**, on the token path. Keyed by the verified `issuer:subject`, enforced in
  `issue` / `revoke` / `explain` right after verification. This covers an authenticated-but-abusive client hammering the
  upstream APIs.

A request always draws from the IP bucket, and from the principal bucket once its identity is known. Either being empty
yields `429 Too Many Requests`.

## Cost model

Cost is a function of `(category, outcome class)`. The category comes from the route (or the service call site); the
outcome class is derived from the HTTP status at the edge (`2xx` success, `401`
auth error, `403` denied, other `4xx` client error, `5xx` server error) or from the internal outcome on the token path.

Defaults (override any cell under `rate_limit.costs`):

| category        | success | denied | auth_error | client_error | server_error |
|-----------------|---------|--------|------------|--------------|--------------|
| `issue`         | 1       | 4      | 10         | 3            | 1            |
| `revoke`        | 1       | 4      | 10         | 3            | 1            |
| `explain`       | 1       | 2      | 8          | 2            | 1            |
| `providers`     | 2       | 2      | 8          | 2            | 1            |
| `resolve`       | 2       | 2      | 8          | 2            | 1            |
| `audit`         | 3       | 3      | 8          | 2            | 1            |
| `task_trigger`  | 8       | 8      | 8          | 4            | 1            |
| `session_login` | 2       | 2      | 10         | 3            | 1            |
| `webhook`       | 1       | 1      | 10         | 2            | 1            |
| default         | 2       | 3      | 8          | 2            | 1            |

Clean requests are cheap; auth failures and heavy operations are expensive; `5xx` is cheap on purpose, so clients are
not punished for our own outages.

## Client IP behind a proxy

Behind an ingress or load balancer, the TCP peer is the proxy, not the client. Set
`trusted_proxies` to the CIDRs of your proxies: when the peer is trusted, Talmi takes the rightmost
`X-Forwarded-For` hop that is not itself a trusted proxy; otherwise it uses the peer directly.

The default is to trust nothing and use the peer, which is correct when Talmi is the edge and safe out of the box: an
untrusted client cannot spoof `X-Forwarded-For` to rotate keys and evade the limit.

## Configuration

```yaml
rate_limit:
  enabled: true
  backend: memory                 # memory | redis
  redis:
    addr: redis:6379
    password: env:REDIS_PASSWORD  # a super secret ref
    db: 0
  trusted_proxies: [ "10.0.0.0/8" ]  # peers whose X-Forwarded-For we trust
  bypass_cidrs: [ "10.1.2.0/24" ] # internal callers that skip limiting entirely
  ip:
    capacity: 60
    refill_per_sec: 1
  principal:
    capacity: 120
    refill_per_sec: 2
  costs: # optional overrides of the default table
    issue:
      auth_error: 12
    task_trigger:
      success: 10
```

| Field             | Meaning                                                                                          |
|-------------------|--------------------------------------------------------------------------------------------------|
| `enabled`         | Turns limiting on. When `false`, `config vet` warns that the endpoint is unprotected.            |
| `backend`         | `memory` (per instance) or `redis` (shared across replicas). Empty means `memory`.               |
| `redis`           | Connection for the `redis` backend. `password` is a [`secret.Ref`](../configuration/secrets.md). |
| `trusted_proxies` | Proxy CIDRs whose `X-Forwarded-For` is trusted for client-IP derivation.                         |
| `bypass_cidrs`    | Client CIDRs that skip both layers entirely.                                                     |
| `ip`              | Bucket shape for the per-IP layer: `capacity` (burst) and `refill_per_sec`.                      |
| `principal`       | Bucket shape for the per-principal layer.                                                        |
| `costs`           | Per-`(category, class)` overrides; unspecified cells keep their defaults.                        |

Configuration lives only in the trusted bootstrap file, never in the sourced tree: limits are an operator concern, not
something a config author should control.

## Backends and failure behavior

- **`memory`** keeps buckets in a sharded in-memory map with a background sweeper that evicts idle keys. Fine for a
  single instance; state does not survive a restart and is not shared.
- **`redis`** keeps buckets in Redis via atomic Lua scripts, so all replicas share one view. If Redis is unavailable,
  the limiter transparently falls back to a local in-memory bucket, logs it, and counts the fallback. This never fails
  open and never self-DoSes; during a Redis outage the effective limit degrades to per-instance.

The limiter is a stable component: it survives config reloads and does not reset its state.

## Responses

A throttled request gets `429 Too Many Requests` with `Retry-After` (seconds until it can retry) and a small JSON body
carrying the correlation id. Every response also carries the draft IETF
`RateLimit-Limit`, `RateLimit-Remaining`, and `RateLimit-Reset` headers for the tightest bucket that applied, so a
well-behaved client can pace itself. `/healthz` and `/icanhaztalmi` are always exempt, as are any `bypass_cidrs` peers.
