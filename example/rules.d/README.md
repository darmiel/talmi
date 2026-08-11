# `rules.d/` — who may request what

Files here define **rules**. A rule maps identity to grants: a `match` (which
principals it applies to) and a list of `allow` entries (what those principals
may request).

Each `*.yaml` file is a **list** of rules. Rules need a unique `name`.

```yaml
- name: ci-read
  description: "optional, human context"
  match:
    issuer: dev-ci          # required: which issuer produced the principal
    allow_empty: true       # match every principal from that issuer
  allow:
    - resources: [ "ghes-corp:acme/*" ]
      actions:   [ "contents:read" ]
```

## The decision model (important)

- **Union, order-independent.** *Every* rule whose `match` accepts the principal
  contributes its `allow` entries. A requested `resource + action` is granted
  only if the **union** of all those allows covers it. Rule order never changes
  the outcome.
- **All-or-nothing per request.** If *any* requested resource+action is left
  uncovered, the whole request is denied.
- **Bounded by capability.** A grant is still capped by the realm/provider
  capability (see [`../realms.d/`](../realms.d)); rules cannot exceed the ceiling.
- **Fail-closed.** No matching rule ⇒ denied. Empty action list ⇒ denied. Empty
  condition without `allow_empty` ⇒ matches nobody.

## `match` — selecting principals

`match.issuer` is required and must reference a defined issuer. Then choose
**exactly one** of `condition`, `expr`, or `allow_empty: true`.

### `condition`
Filters on principal attributes. Short forms cover the common cases:

```yaml
condition:
  team: platform                    # equality shorthand
  email: { contains: "@corp.com" }  # operator form
```

Listing several keys means **all** must hold (implicit AND). For explicit logic
use `all`, `any`, `not`:

```yaml
condition:
  all:
    - sub: { contains: "repo:my-org/" }
    - not: { environment: "sandbox" }
```

**Operators:** `equals` (default), `contains` (substring for strings, membership
for lists), `in` (value ∈ given list), `exists`.

> If an attribute name collides with an operator (`in`, `equals`, …) or with a
> structural key (`key`, `value`, `operator`, `all`, `any`, `not`), use the long
> form so it isn't misparsed:
> ```yaml
> condition:
>   key: value          # the attribute literally named "value"
>   operator: equals
>   value: something
> ```

### `expr`
For matching a `condition` can't express, use an [expr-lang](https://expr-lang.org)
expression returning a bool. Use `expr` **or** `condition`, never both. The
principal is exposed as `ctx` (attributes + `iss`/`sub`/`id`/`issuer`):

```yaml
match:
  issuer: corp-oidc
  expr: 'ctx.repository_owner == "my-org" && ctx.event_name == "push"'
```

> A runtime error or non-bool result is treated as **no match** (fail-closed).

### `allow_empty`
An empty/absent condition denies by default. Set `allow_empty: true` to make a
rule match **every** principal from its issuer.

## `allow` — granting resources

Each `allow` entry needs `resources` (glob patterns, `realm:body`) and `actions`.
Semantics are realm-specific:

- **github-app:** `contents:write`, `actions:read`, … levels `none<read<write<admin`.
- **artifactory:** bare levels `read<annotate<write`.
- **talmi:** exact strings, unordered (`login`, `read`, `trigger`).

```yaml
allow:
  - { resources: [ "ghes-corp:acme/svc-*" ], actions: [ "contents:write" ] }
  - { resources: [ "talmi:tasks", "talmi:tasks/*" ], actions: [ "read", "trigger" ] }
```

Glob rules: `*` does **not** cross `/`, so `acme/*` matches `acme/web` but not
`acme/group/repo`. The requested resource is matched **literally** against the
pattern — request bodies are not themselves globs.

## Anti-footguns

- **Identity can't be spoofed.** `iss`/`sub`/`id`/`issuer` in `ctx`/conditions
  are the server-verified values; a token claim of the same name is ignored.
- **`not` over a missing attribute matches.** `not: { role: admin }` is true for
  a principal with *no* `role` at all, not just non-admins. Combine with
  `exists` if that matters.
- **Sessions re-match the login issuer.** Admin rules use the `github-oauth`
  issuer name; the restored session carries that same issuer.

Validate everything before shipping:

```bash
talmi config vet talmi.yaml            # structural checks
talmi config vet talmi.yaml --online   # also probe providers for coverage
talmi why --token "$TOK" --resource "ghes-corp:acme/x=contents:write"  # explain a decision
```
