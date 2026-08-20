# Running the server

The server is `talmi server run`.

```bash
talmi server run --config talmi.yaml --addr :8080
```

## Flags

| Flag             | Default      | Purpose                                                                                    |
|------------------|--------------|--------------------------------------------------------------------------------------------|
| `-c`, `--config` | `talmi.yaml` | Bootstrap config file.                                                                     |
| `--addr`         | `:8080`      | Address to listen on.                                                                      |
| `--dev`          | off          | Replace every real provider with an in-memory stub and skip the config-error startup gate. |
| `--local`        | off          | Force the local config source, ignoring a configured remote.                               |
| `--ref`          |              | Override the git ref for a GitHub config source.                                           |

Global flags (`--log-level`, `--log-format`, `--no-color`) apply too.

## Dev mode

`--dev` replaces every provider with an in-memory stub that returns dummy tokens, and skips the startup config-error
gate. There is no code path that builds a real provider under `--dev`, so you can exercise policy and leases with no
GitHub or Artifactory credentials. Without a configured signing key, `--dev` generates an ephemeral ES256 key (sessions
won't survive a restart).

This is why `lease explain` (policy only) can succeed while `lease issue` fails under `--dev`: a pure-`api` realm's stub
advertises no capability, so the resolver finds no provider to mint from. See
[Capabilities](../concepts/capabilities.md).

## Endpoints

The HTTP surface (all under `/v2`, except health):

| Method + path                                  | Purpose                                      |
|------------------------------------------------|----------------------------------------------|
| `GET /healthz`                                 | Liveness/readiness probe.                    |
| `GET /icanhaztalmi`                            | Build/version info.                          |
| `POST /v2/token/issue`                         | Issue a lease (bearer = upstream token).     |
| `POST /v2/token/revoke`                        | Revoke a lease (bearer = revocation secret). |
| `POST /v2/token/explain`                       | Dry-run a decision.                          |
| `POST /v2/webhooks/github`                     | Config reload webhook (HMAC-verified).       |
| `GET /v2/auth/config`, `POST /v2/auth/session` | Admin login (device flow).                   |
| `GET /v2/audit`, `GET /v2/audit/{id}`          | Audit query (admin).                         |
| `GET /v2/providers`, `POST /v2/resolve`        | Provider inspection (admin).                 |
| `GET/POST /v2/tasks/...`                       | Background task inspection/trigger (admin).  |

Admin endpoints are guarded per-handler by a session + a `talmi:*` authorization. See
[Sessions and admin](../how-to/enable-admin-access.md).

## Shutdown

`SIGINT`/`SIGTERM` triggers a graceful shutdown: the listener stops, in-flight requests drain, and background tasks
finish before exit.
