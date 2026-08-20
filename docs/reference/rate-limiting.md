# Rate limiting

Reference for the `rate_limit` bootstrap section, the cost table, and the response headers. For the setup walkthrough,
see [Configure rate limiting](../how-to/rate-limiting.md); for the model, see the
[how-to's overview](../how-to/rate-limiting.md#the-model-a-token-bucket-with-debt).

## Configuration

`rate_limit` lives only in the trusted bootstrap file, never in the sourced tree.

```yaml
rate_limit:
  enabled: true
  backend: memory                 # memory | redis
  redis:
    addr: redis:6379
    password: env:REDIS_PASSWORD
    db: 0
  trusted_proxies: [ "10.0.0.0/8" ]
  bypass_cidrs:    [ "10.1.2.0/24" ]
  ip:        { capacity: 60,  refill_per_sec: 1 }
  principal: { capacity: 120, refill_per_sec: 2 }
  costs:
    issue:        { auth_error: 12 }
    task_trigger: { success: 10 }
```

| Field                      | Type          | Default  | Meaning                                                                          |
|----------------------------|---------------|----------|----------------------------------------------------------------------------------|
| `enabled`                  | bool          | `false`  | Turns limiting on. When `false`, `config vet` warns the endpoint is unprotected. |
| `backend`                  | string        | `memory` | `memory` (per instance) or `redis` (shared across replicas).                     |
| `redis.addr`               | string        | -        | Required when `backend: redis`.                                                  |
| `redis.password`           | `secret.Ref`  | -        | Optional Redis password.                                                         |
| `redis.db`                 | int           | `0`      | Redis database number.                                                           |
| `trusted_proxies`          | list of CIDRs | none     | Proxy CIDRs whose `X-Forwarded-For` is trusted for client-IP derivation.         |
| `bypass_cidrs`             | list of CIDRs | none     | Client CIDRs that skip both layers entirely.                                     |
| `ip.capacity`              | int           | -        | Burst ceiling for the per-IP bucket.                                             |
| `ip.refill_per_sec`        | number        | -        | Tokens added per second to the per-IP bucket.                                    |
| `principal.capacity`       | int           | -        | Burst ceiling for the per-principal bucket.                                      |
| `principal.refill_per_sec` | number        | -        | Tokens added per second to the per-principal bucket.                             |
| `costs`                    | map           | defaults | Per-`(category, class)` overrides; unspecified cells keep their defaults.        |

`capacity` and `refill_per_sec` must be positive; CIDRs must parse; costs must be non-negative.
`config vet` reports any violation as `CFG-RATELIMIT`.

## Cost table

Cost is a function of `(category, outcome class)`. The category comes from the route (edge) or the service call site;
the outcome class comes from the HTTP status (`2xx` success, `401` auth error,
`403` denied, other `4xx` client error, `5xx` server error) or the internal outcome on the token path.

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

Clean requests are cheap; auth failures and heavy operations are expensive; `5xx` is cheap so clients are not punished
for server-side outages. Override any cell under `costs`; unspecified cells keep the default.

## Backends and failure behavior

- **`memory`** keeps buckets in a sharded in-memory map with a background sweeper that evicts idle keys. Fine for a
  single instance; state does not survive a restart and is not shared.
- **`redis`** keeps buckets in Redis via atomic Lua scripts, so all replicas share one view. If Redis is unavailable,
  the limiter falls back to a local in-memory bucket, logs it, and counts the fallback. It never fails open; during a
  Redis outage the effective limit degrades to per-instance.

The limiter is a stable component: it survives config reloads without resetting its state.

## Response headers

- On rejection: `429 Too Many Requests` with `Retry-After` (seconds until the bucket is positive again) and a small JSON
  body carrying the correlation id.
- On every response: `RateLimit-Limit`, `RateLimit-Remaining`, and `RateLimit-Reset` (draft IETF fields) for the
  tightest bucket that applied.
- `/healthz` and `/icanhaztalmi` are always exempt, as are `bypass_cidrs` peers.
