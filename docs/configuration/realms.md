# Realms and providers


Realm blocks live under `realms.d/`. Each block has a `type` (the backend), and optionally a `realm`
name, a `capability` ceiling, and a list of `instances`. See
[Concepts > Realms and providers](../concepts/realms-and-providers.md) and
[Capabilities and discovery](../concepts/capabilities.md) for the model behind these fields.


## Realm block structure


Every realm block shares the same shape. The provider `type` decides which fields an instance takes.


```yaml
- realm: ghes-corp          # optional; defaults from type (see below)
  type: github-app          # required: github-app | artifactory | talmi
  capability: # optional ceiling for the whole realm
    discovery: api           # api | static (default depends on type)
    refresh_interval: 15m    # capability cache TTL, only meaningful for api discovery
    resources: [ "ghes-corp:acme/*" ]
    max_actions: [ "contents:write", "actions:write" ]
  instances: # provider credentials; one realm can hold several
    - name: gh-writer        # required, unique within the realm
      capability: { }        # optional per-instance override of the realm capability
      # ... provider-specific keys (see each provider below)
```


| Field                    | Required | Meaning                                                                                      |
|--------------------------|----------|----------------------------------------------------------------------------------------------|
| `realm`                  | no       | Namespace for resources. Defaults from `type`; declaring it silences a `config vet` warning. |
| `type`                   | yes      | Provider backend: `github-app`, `artifactory`, or `talmi`.                                   |
| `capability`             | no       | The ceiling of what the realm may ever hand out. See [capability block](#capability-block).  |
| `instances`              | see type | Provider credentials. `github-app` and `artifactory` need at least one; `talmi` takes none.  |
| `instances[].name`       | yes      | Instance identifier, unique within the realm.                                                |
| `instances[].capability` | no       | Overrides the realm `capability` for that one instance.                                      |


### Capability block


`capability` bounds the realm; it is the intersection point with the policy, so a rule can never
grant more than the capability allows.


| Field              | Type        | Meaning                                                                                 |
|--------------------|-------------|-----------------------------------------------------------------------------------------|
| `discovery`        | string      | `api` (query the backend for the live ceiling) or `static` (trust the declared lists).  |
| `refresh_interval` | duration    | Cache TTL for `api` discovery (e.g. `15m`). Ignored for `static`. `0` uses the default. |
| `resources`        | glob list   | Resource patterns the realm may serve, written `<realm>:<glob>`.                        |
| `max_actions`      | action list | The action ceiling. Requests above it are denied before any provider is called.         |


Under `api` discovery with declared lists, the effective ceiling is the intersection of what the
backend reports and what you declared. Full details in
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


Mints GitHub App installation tokens. Capability is discovered live from the App by default
(installations, repos, permissions), so the declared lists act as a ceiling and as documentation.

A resource body is `<owner>/<repo>` (globs allowed, `*` does not cross `/`). Actions are
`<permission>:<level>` with levels ordered `none < read < write < admin`. See
[Resources, actions, and rules](../concepts/resources-actions-rules.md) for the action grammar.


```yaml
- realm: ghes-corp
  type: github-app
  capability:
    discovery: api               # default for github-app
    refresh_interval: 15m        # capability cache TTL (api discovery)
    resources: [ "ghes-corp:acme/*" ]
    max_actions: [ "contents:write", "actions:write" ]
  instances:
    - name: gh-writer
      app_id: 222
      private_key: file:/run/secrets/writer.pem
      server: https://github.example.com/    # omit for github.com
      timeout: 30s                            # optional HTTP timeout
```


| Instance field | Required | Type       | Meaning                                                            |
|----------------|----------|------------|--------------------------------------------------------------------|
| `app_id`       | yes      | integer    | GitHub App ID. Must be positive.                                   |
| `private_key`  | yes      | secret ref | The App's PEM private key. Use a `file:`/`env:` ref, never inline. |
| `server`       | no       | URL        | GHES base URL. Omit for github.com.                                |
| `timeout`      | no       | duration   | HTTP timeout for calls to GitHub. `0` uses the default (30s).      |


Run a read-only App and a write App as two instances in the same realm: the resolver sends a read
request to the read-only App and only reaches for the write App when a write is asked for. See
[least-privileged selection](../concepts/realms-and-providers.md#least-privileged-selection).


## `artifactory`


Mints JFrog Artifactory access tokens. Capability is declarative (`static`): the token is scoped to
the configured `groups`, so the declared `resources`/`max_actions` are the ceiling.

A resource body is a repository path (globs allowed). Actions are bare levels ordered
`read < annotate < write`.


```yaml
- realm: artifactory
  type: artifactory
  capability:
    discovery: static            # default for artifactory
    resources: [ "artifactory:docker-local/*" ]
    max_actions: [ "write" ]
  instances:
    - name: art-main
      admin_token: env:ARTIFACTORY_ADMIN_TOKEN
      groups: [ ci-deployers ]
      base_url: https://artifactory.example.com
      timeout: 30s
```


| Instance field | Required | Type        | Meaning                                                                      |
|----------------|----------|-------------|------------------------------------------------------------------------------|
| `admin_token`  | yes      | secret ref  | Admin access token used to mint scoped tokens. Use a `file:`/`env:` ref.     |
| `groups`       | yes      | string list | At least one group. The minted token is scoped to these groups' permissions. |
| `base_url`     | no       | URL         | Artifactory base URL.                                                        |
| `timeout`      | no       | duration    | HTTP timeout for calls to Artifactory. `0` uses the default (30s).           |


A token with no groups would be unscoped, so Talmi refuses to mint one and the `groups` list is
required.


## `talmi`


The session realm. It has no provider backend and mints nothing. It exists so the admin resources
(`talmi:session`, `talmi:audit`, `talmi:providers`, `talmi:tasks`) have semantics that rules can
grant. Declare it once, with no instances:


```yaml
- realm: talmi
  type: talmi
  instances: [ ]
```


Its actions are exact strings with no ordering (e.g. `login`, `read`, `trigger`), so `read` does not
imply `trigger`.


## Development stub


`talmi server run --dev` replaces every provider above with an in-memory stub that returns dummy
tokens and skips the config-error startup gate. It is not a realm type you configure; it lets you
exercise policy and leases without real GitHub or Artifactory credentials. See
[Quick start](../getting-started/quick-start.md) and [Running the server](../operations/server.md).
