# Resources, actions, and rules

## Resources and actions

A resource is written `<realm>:<body>`, where the body is a glob. Actions are strings whose meaning
depends on the realm:

- **`github-app`** - actions are `<permission>:<level>`, e.g. `contents:write`, `actions:read`.
  Levels are ordered `none < read < write < admin`, so granting `contents:write` covers a request for
  `contents:read`. The permission name is case-sensitive; the level is case-insensitive.
- **`artifactory`** - actions are bare levels, ordered `read < annotate < write` (case-insensitive).
- **`talmi`** - actions are exact strings with no ordering, e.g. `login`, `read`, `trigger`
  (case-sensitive: `read` does not imply `trigger`).

Glob rules: `*` does not cross `/`, so `acme/*` matches `acme/web` but not `acme/group/repo`.

Examples: `ghes-corp:acme/*=contents:read`, `talmi:audit=read`.

## Rules

Rules map identity to grants. A rule has a `match` (which principals it applies to) and a list of
`allow` entries (what those principals may request). Every rule whose `match` accepts the principal
contributes its `allow` entries, and a requested resource is granted only if that union covers it. If
any requested resource is left uncovered, the whole request is denied. Rule order does not change the
outcome, so group rules however you like.

```yaml
- name: talmi-admins
  match:
    issuer: gh-human
    condition:
      teams: { contains: "talmi-dev-poc/admin-users" }
  allow:
    - { resources: [ "talmi:session" ], actions: [ "login" ] }
    - { resources: [ "talmi:audit" ],   actions: [ "read" ] }
    - { resources: [ "talmi:tasks", "talmi:tasks/*" ], actions: [ "read", "trigger" ] }
```

A rule's `match` uses either a [condition](conditions.md) or an `expr` (not both). An empty condition
denies by default; set `allow_empty: true` to make a rule match every principal from its issuer.

The effective grant is always the overlap of the policy (rules) and the realm's
[capability](capabilities.md) ceiling: a rule cannot grant more than the realm can mint.
