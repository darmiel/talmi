# Audit events

Every decision Talmi makes is written to the audit log as one event, including denials. Events are append-only: they are
written once, queried, and pruned only for retention. Query them with
`talmi audit list` / `talmi audit inspect`, or via the admin API. See [Auditing](../security/auditing.md)
for how the log is stored and retained.

## Actions

| Action             | When it is written                                          | Outcomes                       |
|--------------------|-------------------------------------------------------------|--------------------------------|
| `lease.issue`      | A token issuance request (`/v2/token/issue`).               | `success`, `denied`, `failure` |
| `lease.revoke`     | A revocation request (`/v2/token/revoke`).                  | `success`, `failure`           |
| `session.login`    | An admin session login.                                     | `success`, `failure`           |
| `task.trigger`     | A background task is triggered by an admin.                 | `success`, `failure`           |
| `authz.denied`     | An admin call fails session verification or authorization.  | `denied`                       |
| `config.reload`    | The sourced config is reloaded (startup, sync, or webhook). | `success`, `failure`           |
| `webhook.received` | A GitHub config webhook is received.                        | `success`, `failure`           |

## Outcomes

| Outcome   | Meaning                                                                       |
|-----------|-------------------------------------------------------------------------------|
| `success` | The action completed.                                                         |
| `denied`  | Policy denied the request (a valid identity without the required grant).      |
| `failure` | The action failed for another reason (verification, resolution, or an error). |

## Event fields

| Field        | Description                                                                                  |
|--------------|----------------------------------------------------------------------------------------------|
| `id`         | Server-generated event id, distinct from any lease id.                                       |
| `time`       | When the event was recorded.                                                                 |
| `action`     | One of the actions above.                                                                    |
| `outcome`    | One of the outcomes above.                                                                   |
| `actor`      | The verified principal, when there is one.                                                   |
| `request_id` | Correlation id for the request.                                                              |
| `session_id` | Admin session id (jti), for admin actions.                                                   |
| `revision`   | The config revision in effect when the event was recorded.                                   |
| `error`      | A message for `denied`/`failure` outcomes (the deny reason or error).                        |
| `metadata`   | Action-specific extras, for example `lease_id`, `revoked_count`, or `task`.                  |
| `decision`   | The authorization decision trace (lease events).                                             |
| `artifacts`  | The minted artifacts, each with `artifact_id`, `provider`, and `fingerprint` (lease events). |

A single request writes exactly one event with its artifacts nested inside, never one event per artifact. The
`fingerprint` on an artifact traces a leaked token back to the issuing request and lease.

## Querying

Filter by any indexed field:

```bash
talmi audit list --action lease.issue --outcome denied --since 2026-08-01T00:00:00Z --limit 50
talmi audit inspect <event-id>          # full decision trace and artifacts
talmi audit list --fingerprint <fp>     # find the request that minted a specific token
```

See the [CLI reference](../cli.md) for every flag.
