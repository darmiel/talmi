# Rules

Rules live under `rules.d/`. Each rule has a `match` and a list of `allow` entries. See
[Concepts > Resources, actions, rules](../concepts/resources-actions-rules.md) and
[Conditions](../concepts/conditions.md). For a step-by-step walkthrough, see
[Write and test policy rules](../how-to/write-rules.md).

```yaml
- name: dev-read
  match:
    issuer: gh-actions
    condition:
      repository: { contains: "acme/" }
  allow:
    - resources: [ "github:acme/*" ]
      actions: [ "contents:read" ]

- name: deploy-write
  match:
    issuer: gh-actions
    condition:
      all:
        - repository: { in: [ "acme/svc-a", "acme/svc-b" ] }
        - ref: "refs/heads/main"
  allow:
    - resources: [ "github:acme/svc-a", "github:acme/svc-b" ]
      actions: [ "contents:write" ]
```

## `match`

- `issuer` (required) - the issuer name this rule applies to.
- `condition` - a filter over principal attributes (short form, or `all`/`any`/`not`). See
  [Conditions](../concepts/conditions.md).
- `expr` - an expression, as an alternative to `condition` (not both).
- `allow_empty: true` - match every principal from the issuer when there is no condition. Without it, a rule with no
  condition matches no one.

## `allow`

Each entry lists `resources` (realm-prefixed globs) and `actions`. A request is authorized only if the union of `allow`
entries from all matching rules covers every requested resource and action, and never exceeds the
realm's [capability](../concepts/capabilities.md) ceiling.

## Admin rules

Admin access is granted with `talmi:*` resources:

```yaml
- name: talmi-admins
  match:
    issuer: gh-login
    condition:
      teams: { contains: "my-org/talmi-admins" }
  allow:
    - { resources: [ "talmi:session" ],   actions: [ "login" ] }
    - { resources: [ "talmi:audit" ],     actions: [ "read" ] }
    - { resources: [ "talmi:providers" ], actions: [ "read" ] }
    - { resources: [ "talmi:tasks", "talmi:tasks/*" ], actions: [ "read", "trigger" ] }
```

`talmi` actions are exact strings with no ordering: `read` does not imply `trigger`.
