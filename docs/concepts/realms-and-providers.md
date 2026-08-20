# Realms and providers

A *realm* is a namespace of resources with its own meaning of "resource" and "action". A *provider*
is the backend that actually mints tokens for a realm. A realm block's `type` picks the backend, and everything a realm
can ever hand out is bounded by its *capability*.

This page covers the model. For the config fields (what each provider block looks like, which keys are required),
see [Configuration > Realms and providers](../reference/realms.md).

## Provider types

Talmi ships three realm types. They differ in what they mint and in how their capability ceiling is determined:

- **`github-app`** mints GitHub App installation tokens. Its capability is *discovered live* from the App: Talmi queries
  the installations, repos, and permissions the App actually has, and the declared lists narrow that down. A resource is
  an `<owner>/<repo>` and actions are `<permission>:<level>`.
- **`artifactory`** mints JFrog Artifactory access tokens. Its capability is *declarative*: the token is scoped to
  configured groups, so what you declare is the ceiling. A resource is a repository path and actions are bare levels
  (`read < annotate < write`).
- **`talmi`** is the session realm. It has no backend and mints nothing. It exists so the admin resources
  (`talmi:session`, `talmi:audit`, `talmi:providers`, `talmi:tasks`) have semantics that rules can grant.

The [Resources, actions, and rules](resources-actions-rules.md) page has the full action grammar for each type.

## Realms, instances, and capability

A realm can hold several `instances`, one per App or server. Each instance carries its own credentials but serves the
same realm namespace. Capability is the ceiling of what the realm may ever hand out (which resources, up to which action
level); an instance can tighten it further.

The grant a caller actually gets is always the overlap of two things: the policy (the union of
matching [rules](resources-actions-rules.md)) and the realm's [capability](capabilities.md). A rule can never grant more
than the realm can mint, and the realm can never mint more than its backend allows.
See [Capabilities and discovery](capabilities.md) for how the effective ceiling is computed from a static declaration
versus live discovery.

## Least-privileged selection

When several instances in a realm can serve a resource, the resolver does not pick the first match. It picks the
instance whose ceiling most tightly fits the request: narrowest action level first, then narrowest resource breadth,
then declaration order as a tiebreak. The request only ever reaches an instance powerful enough to serve it, and no
more.

Consider a `ghes-corp` realm with two GitHub App instances:

```yaml
# realms.d/ghes-corp.yaml
- realm: ghes-corp
  type: github-app
  instances:
    - name: gh-readonly     # App installed with Contents: Read-only
      app_id: 111
      private_key: file:/run/secrets/gh-readonly.pem
    - name: gh-readwrite    # App installed with Contents: Read and write
      app_id: 222
      private_key: file:/run/secrets/gh-readwrite.pem
```

- A request for `ghes-corp:acme/svc-a=contents:read` is served by `gh-readonly`. Both Apps could serve it, but the
  read-only one is the tighter fit, so the minted token cannot write even though a write-capable App exists in the
  realm.
- A request for `ghes-corp:acme/svc-a=contents:write` skips `gh-readonly` (it cannot write) and is served by
  `gh-readwrite`.

The same logic applies to resource breadth: an instance scoped to `acme/*` is preferred over one scoped to `*` for a
resource under `acme/`, so a token is never broader than it needs to be.

### Inspecting the choice

Two admin commands show what the running server would do, without minting anything:

```bash
talmi provider list                                          # instances and their live capability
talmi provider resolve "ghes-corp:acme/svc-a=contents:read"  # which instance would serve this
talmi provider resolve --verbose "ghes-corp:acme/svc-a=contents:write"  # per-candidate breakdown
```

`--verbose` shows every candidate instance and why each was or was not chosen, which is the fastest way to understand a
selection.

## See also

-

How-to: [GitHub App provider](../how-to/github-app-provider.md), [Artifactory provider](../how-to/artifactory-provider.md)

- Concepts: [Capabilities and discovery](capabilities.md)
- Reference: [Realm and provider types](../reference/realms.md)
