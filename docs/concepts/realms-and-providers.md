# Realms and providers

A *realm* is a namespace of resources with its own meaning of "resource" and "action". A *provider*
is the backend that actually mints tokens for a realm. The realm block's `type` picks the backend.

## Provider types

- **`github-app`** - mints GitHub App installation tokens. Instance config: `app_id`, `private_key`,
  optional `server` (for GHES), optional `timeout`.
- **`artifactory`** - mints JFrog Artifactory access tokens. Instance config: `admin_token`,
  `groups`, optional `base_url`, optional `timeout`.
- **`talmi`** - the session realm. It has no provider backend and mints nothing. It exists so admin
  resources (`talmi:session`, `talmi:audit`, `talmi:providers`, `talmi:tasks`) have semantics that
  rules can grant.

## Realms, instances, capability

A realm can hold several `instances` (individual Apps/servers). `capability` sets what the realm may
ever hand out (`resources` globs, `max_actions` ceiling); an instance can override it. `realm:` is
optional and defaults from the type (`github-app` -> `github`, `artifactory` -> `artifactory`,
`talmi` -> `talmi`).

```yaml
- realm: ghes-corp
  type: github-app
  capability:
    resources: [ "ghes-corp:acme/*" ]
    max_actions: [ "contents:read", "contents:write" ]
  instances:
    - name: gh-ci-reader
      app_id: 111
      private_key: file:/run/secrets/reader.pem
    - name: gh-ci-writer
      app_id: 222
      private_key: file:/run/secrets/writer.pem
```

The session realm is declared once with no instances:

```yaml
- realm: talmi
  type: talmi
  instances: [ ]
```

## Least-privileged selection

When several instances can serve a resource, the resolver picks the one whose action ceiling most
tightly fits the request (then by resource breadth, then declaration order). That is why you can run
a read-only App and a write App in the same realm: a read request goes to the read-only App.

See [Capabilities and discovery](capabilities.md) for how a realm's effective capability is computed
(static declaration vs. live discovery), and
[Configuration > Realms and providers](../configuration/realms.md) for the full config surface.
