# Bootstrap (`talmi.yaml`)

The bootstrap file is the trusted, host-local entry point. A JSON Schema is available for editor validation -
see [Validation](validation.md).

```yaml
# talmi.yaml
grade: prod                      # free-form label for your environment

store:
  type: postgres                 # memory | postgres
  dsn: env:TALMI_STORE_DSN       # required for postgres
  connect_timeout: 10s           # 0 = default

audit:
  enabled: true
  type: postgres                 # postgres | memory | noop
  dsn: env:TALMI_AUDIT_DSN
  retention: 2160h              # 90 days (0/unset = keep forever)
  connect_timeout: 10s
  sinks: [ stdout ]              # optional: export each event

signing:
  algorithm: ES256               # ES256 (default) | HS256
  key: file:/run/secrets/session-signing-key.pem

auth: # enables the admin API (optional)
  login_issuer: gh-login       # a github-oauth issuer
  session_issuer: talmi-session  # a talmi-session issuer
  session_ttl: 8h
  server: https://github.com
  client_id: Iv1.xxxxxxxx
  scopes: [ read:org ]

rate_limit: # protects the public endpoint (optional)
  enabled: true
  backend: memory                # memory | redis
  ip: { capacity: 60,  refill_per_sec: 1 }
  principal: { capacity: 120, refill_per_sec: 2 }

source: # where the sourced tree comes from (optional)
  github: ... # ...local includes or a github block; see Config sources

issuers: { include: [ "issuers.d/*.yaml" ] }
realms: { include: [ "realms.d/*.yaml" ] }
rules: { include: [ "rules.d/*.yaml" ] }
```

## Sections

| Section                        | Purpose                                                                                                             |
|--------------------------------|---------------------------------------------------------------------------------------------------------------------|
| `store`                        | Lease registry. `memory` (default) or `postgres` with a `dsn`. `connect_timeout` bounds the initial connect.        |
| `audit`                        | Audit log. `enabled`, `type`, `dsn`, `retention` (a duration; `0`/unset keeps forever), `sinks`.                    |
| `signing`                      | Session JWT signing key. `ES256` (EC PEM) or `HS256` (raw secret).                                                  |
| `auth`                         | Admin API. Names a `login_issuer` and `session_issuer`, plus OAuth `server`/`client_id`/`scopes` and `session_ttl`. |
| `rate_limit`                   | Per-IP and per-principal throttling of the public endpoint. See [Rate limiting](../how-to/rate-limiting.md).        |
| `source`                       | Local includes or a remote GitHub source. See [Config sources](config-sources.md).                                  |
| `issuers` / `realms` / `rules` | Glob includes for the sourced tree.                                                                                 |

Every secret-bearing value (`dsn`, `key`, provider credentials) is a [`secret.Ref`](secrets.md):
`file:` or `env:`, or `raw:` for local testing.

Postgres is not auto-migrated by the app; run migrations out of band (see
[Deployment](../how-to/deploy-kubernetes.md)).
