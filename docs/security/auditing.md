# Auditing

Every request is recorded, including denials. Auditing is configured in the bootstrap
[`audit`](../reference/bootstrap.md) block and queried with `talmi audit` (needs a session with
`talmi:audit=read`).

## Querying

```bash
talmi audit list --limit 50
talmi audit list --action lease.issue --principal my-pipeline/my-job
talmi audit list --outcome denied --since 2026-01-01T00:00:00Z --json
talmi audit list --request-id "<correlation-id>"   # every event from one request
talmi audit list --session-id "<jti>"              # every action in one login
talmi audit inspect "<entry-id>"                    # one entry, with its decision trace
```

Each event carries its own id, the request `X-Correlation-ID` (`request_id`), and, for actions inside an admin login, a
`session_id`. Those three ids let you trace one event, one request, or a whole login session.

## Retention and sinks

- `retention` (a duration in the `audit` block) enables a daily prune of entries older than the window. Unset or `0`
  keeps everything.
- `sinks: [ stdout ]` exports each event to an external collector as it is written.

## Tracing a token back to a decision

Talmi records a *fingerprint* of each minted token (for providers that support it), never the token itself. The
fingerprint is the base64-encoded SHA-256 of the token value. When a downstream system shows activity by a token, find
the request that produced it:

```bash
talmi audit list --fingerprint "<fingerprint>"
```

### Why fingerprints: mapping GitHub's audit log to Talmi's

GitHub records a `hashed_token` field on every audit event, which is the SHA-256 of the token that performed the action,
base64 encoded. GitHub's own instructions compute it as `echo -n TOKEN | openssl dgst -sha256 -binary | base64`, see
[Identifying audit log events performed by an access token](https://docs.github.com/en/enterprise-cloud@latest/admin/monitoring-activity-in-your-enterprise/reviewing-audit-logs-for-your-enterprise/identifying-audit-log-events-performed-by-an-access-token).

Talmi computes the fingerprint the same way, so a token's Talmi fingerprint and its GitHub
`hashed_token` are the **same string**. That gives you a two-way join between the logs:

- **GitHub -> Talmi.** GitHub shows a suspicious or interesting action and its `hashed_token`. Search Talmi with
  `talmi audit list --fingerprint "<hashed_token>"` to find the exact request that minted that token: which principal
  asked, under which rule, for which resources.
- **Talmi -> GitHub.** Take a fingerprint from a Talmi lease event and search GitHub's audit log with
  `hashed_token:"<fingerprint>"` to see everything that token did downstream.

Talmi never stores the token value, only this fingerprint (and a hash of the revocation secret), so the join works
without either system holding the raw credential. It turns two disconnected logs into one traceable chain from a
downstream action back to the policy decision that authorized it.

### Replaying the decision

Take the entry id and replay the decision to see the rule-by-rule trace, without minting anything:

```bash
talmi lease explain --replay-id "<entry-id>"
```

`lease explain` also runs ahead of time against a live token, which is the fastest way to understand why a rule did or
didn't match:

```bash
talmi lease explain --token "$OIDC" --resource "ghes-corp:acme/svc-a=contents:write"
```

The trace shows which rules matched and, for each requested resource, whether some grant covered it (and if not, why).
When authorized, it also shows the least-privilege token that *would* be minted.

## Inspecting providers

To see what the running server's providers can serve, and how a request would resolve before anything is minted (needs
`talmi:providers=read`):

```bash
talmi provider list                                       # instances + live effective capability
talmi provider resolve "ghes-corp:acme/x=contents:read"   # which provider would serve it
talmi provider resolve --verbose "ghes-corp:acme/x=contents:write"  # per-candidate breakdown
```

## See also

- Reference: [Audit events](../reference/audit-events.md)
- How-to: [Run with PostgreSQL](../how-to/postgres.md)
