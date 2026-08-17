# Realms and providers

Realm blocks live under `realms.d/`. Each block has a `type` (the backend) and, optionally, a
`realm` name, a `capability` ceiling, and `instances`. See
[Concepts > Realms and providers](../concepts/realms-and-providers.md) and
[Capabilities and discovery](../concepts/capabilities.md).

## Default realm names

`realm:` is optional. When omitted it defaults from the type:

| Type          | Default realm |
|---------------|---------------|
| `github-app`  | `github`      |
| `artifactory` | `artifactory` |
| `talmi`       | `talmi`       |

`config vet` warns when a name is defaulted (declare `realm:` to silence it), a type with no default
still requires an explicit name, and realm names must be unique (a collision is a hard error).

## `github-app`

Mints GitHub App installation tokens. `capability` is discovered live from the App (installations,
repos, permissions) and the declared lists act as a ceiling / documentation.

```yaml
- realm: ghes-corp
  type: github-app
  capability:
    resources: [ "ghes-corp:acme/*" ]
    max_actions: [ "contents:write", "actions:write" ]
    refresh_interval: 15m        # capability cache TTL (api discovery)
  instances:
    - name: gh-writer
      app_id: 222
      private_key: file:/run/secrets/writer.pem
      server: https://github.example.com/   # omit for github.com
      timeout: 30s                            # optional HTTP timeout
```

## `artifactory`

Mints JFrog Artifactory access tokens. Capability is declarative (`static`).

```yaml
- realm: artifactory
  type: artifactory
  capability:
    resources: [ "artifactory:docker-local/*" ]
    max_actions: [ "write" ]
  instances:
    - name: art-main
      admin_token: env:ARTIFACTORY_ADMIN_TOKEN
      groups: [ ci-deployers ]
      base_url: https://artifactory.example.com
      timeout: 30s
```

## `talmi`

The session realm. No backend, no instances - it exists so admin resources
(`talmi:session`, `talmi:audit`, `talmi:providers`, `talmi:tasks`) exist for rules to grant.

```yaml
- realm: talmi
  type: talmi
  instances: [ ]
```

## Capability and discovery

`capability.discovery` controls how the effective ceiling is computed (`static`, `api`, or
type-default). Under `api` with declared lists, the effective set is the intersection of discovered
and declared. Full details in [Capabilities and discovery](../concepts/capabilities.md).
