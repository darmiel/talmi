# Run with PostgreSQL

The in-memory store and auditor are ephemeral: leases and audit records are lost on restart, and they are not shared
across replicas. For anything beyond local runs, back both with PostgreSQL.

## Before you begin

- A running Talmi server you administer.
- A reachable PostgreSQL database and a connection string for it.
- The `migrate` tool ([golang-migrate](https://github.com/golang-migrate/migrate)) to apply the schema. Talmi does not
  migrate the database itself.

## 1. Apply migrations out of band

Talmi never auto-migrates. Run the migrations from `internal/store/postgres/migrations` before starting a version that
expects the schema:

```bash
migrate -path internal/store/postgres/migrations -database "$TALMI_STORE_DSN" up
```

Run this before rolling out a new Talmi version, and as a Kubernetes Job in a pipeline (see
[Deploy to Kubernetes](deploy-kubernetes.md)).

## 2. Point the store and auditor at Postgres

In the bootstrap file, set both `store` and `audit` to `postgres` with a DSN. The DSN is a
[`secret.Ref`](../reference/secrets.md), not an inline string:

```yaml
store:
  type: postgres
  dsn: env:TALMI_STORE_DSN
  connect_timeout: 10s        # bounds the initial connect; 0 = default (10s)

audit:
  enabled: true
  type: postgres
  dsn: env:TALMI_AUDIT_DSN
  retention: 90d              # 0 or unset = keep forever
  connect_timeout: 10s
```

The store and auditor can share one database or use separate ones; they are configured independently.

## 3. Verify

```bash
talmi config vet talmi.yaml --local
talmi server run -c talmi.yaml --addr :8080
```

On startup the log reports the store and auditor as `postgres`. Issue a lease, restart the server, and confirm the lease
is still listed: state now survives restarts. Query the audit log with
`talmi audit list`.

## Edge cases

- **Unreachable database at startup**: the server fails to start rather than running without a store or audit log. Fix
  connectivity or the DSN.
- **Schema drift**: if the running binary expects a newer schema than the database has, migrate first. Roll migrations
  forward before the binary that needs them.
- **Retention**: `retention` prunes audit records older than the duration. Leaving it unset keeps everything, which
  grows unbounded; set it to your compliance window.
- **Secrets**: keep DSNs in `env:`/`file:` refs, never inline. See [Secrets](../reference/secrets.md).

## Next steps

- [Deploy to Kubernetes](deploy-kubernetes.md) with a migration Job.
- [Auditing](../security/auditing.md) and the [audit events reference](../reference/audit-events.md).
