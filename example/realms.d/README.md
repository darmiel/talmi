# `realms.d/`: resource namespaces & the providers that mint them

Files here define **realms**. A realm is a namespace of resources with its own
meaning of "resource" and "action", plus the **provider instances** (apps /
accounts) that actually mint tokens for it.

- A **resource** is written `<realm>:<body>`. The realm prefix routes it, and
  the body is opaque to the core and interpreted by the realm.
- An **action** is a realm-defined string. Realms differ in how actions are
  ordered (see below).

Each `*.yaml` file is a **list** of realm blocks. Blocks need a `realm` (the
prefix) and a `type` (which backend/semantics to use).

```yaml
- realm: ghes-corp          # the resource prefix -> "ghes-corp:owner/repo"
  type: github-app          # github-app | artifactory | talmi
  capability:               # what this realm may hand out (the ceiling)
    resources:   [ "ghes-corp:acme/*" ]
    max_actions: [ "contents:write" ]
  instances:                # individual apps/accounts that mint
    - name: gh-main
      # ...type-specific credentials...
```

## `capability`: the ceiling

`capability` bounds what a realm may ever mint, independent of policy:

| field              | meaning                                                        |
|--------------------|----------------------------------------------------------------|
| `resources`        | glob patterns of resources this realm can serve                |
| `max_actions`      | the highest action level per permission the realm will grant   |
| `refresh_interval` | (github-app) how long discovered capability is cached          |

For `github-app`, `resources`/`max_actions` are **discovered live** from the App
(installations, repos, permissions) and the declared values act as documentation
/ the `--online` vet baseline. For `artifactory` and `talmi` they are declarative.

> Rules grant access within the capability. The effective grant is the overlap
> of the matched rule allows and the realm/provider capability, so a rule can
> never exceed the ceiling.

## Types

### `github-app`
Mints GitHub App **installation tokens**. Resources are `realm:owner/repo` and
actions are `<permission>:<level>` where `none < read < write < admin` (so
granting `contents:write` also satisfies a `contents:read` request).

```yaml
- realm: ghes-corp
  type: github-app
  capability:
    resources:   [ "ghes-corp:acme/*" ]
    max_actions: [ "contents:write", "actions:write" ]
    refresh_interval: 15m
  instances:
    - name: gh-main
      app_id: 111111                          # required
      private_key: file:/run/secrets/app.pem  # required (secret.Ref)
      # server: https://github.example.com/    # optional, for GHES
```

### `artifactory`
Mints JFrog Artifactory access tokens. Actions are bare levels ordered
`read < annotate < write`.

```yaml
- realm: artifactory
  type: artifactory
  capability:
    resources:   [ "artifactory:docker-local/*" ]
    max_actions: [ "write" ]
  instances:
    - name: af-main
      admin_token: env:AF_ADMIN_TOKEN     # required (secret.Ref)
      groups: [ "ci-writers" ]            # required; minted token is scoped here
      base_url: https://artifactory.example.com   # required
```

### `talmi`
The **session realm**. It has no provider backend and mints nothing. It exists
so admin resources have semantics rules can grant. Actions are **exact strings
with no ordering** (e.g. `login`, `read`, `trigger`; `read` does *not* imply
`trigger`).

```yaml
- realm: talmi
  type: talmi
  instances: []          # provider-less
```

Well-known admin resources: `talmi:session` (`login`), `talmi:audit` (`read`),
`talmi:tasks` + `talmi:tasks/*` (`read`, `trigger`).

## Instances & secrets

- Each instance needs a unique `name` (globally unique across all realms).
- Running several instances of the same realm keeps privilege tight (e.g. a
  read-only App and a write-capable App), with rules deciding who reaches which.
  When several instances can serve a request, Talmi picks the **least-privileged**
  one that covers it.
- Secrets are **never inline values**. Use a `secret.Ref`: `raw:literal` (dev
  only), `file:/path`, or `env:VAR_NAME`.

> **Security:** these `file:`/`env:` secrets are resolved on the Talmi host and
> then sent to the `server`/`base_url` this block names. If your realms come
> from a remote config repo, anyone who can push to it can point a provider at a
> URL they control and exfiltrate those host secrets. Only source realms from a
> trusted, access-controlled repo. See the config-source note in the bootstrap
> file.

> **Known limitation:** a per-*instance* `capability:` override is advertised by
> the JSON schema but currently rejected by the instance decoder. Set
> `capability` at the *realm* level and scope per-instance access with rules.
