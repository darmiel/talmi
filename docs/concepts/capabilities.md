# Realm capabilities and discovery

A realm's **capability** is the ceiling of what its provider instances may mint: which
`resources` they can serve and the maximum `max_actions` on them. Rules narrow this per principal;
the capability is the outer bound. How the capability is determined is controlled by
`discovery`.

## Modes

Set `discovery` on a realm's (or an instance's) `capability` block:

| `discovery`            | Effective capability                                                         |
|------------------------|------------------------------------------------------------------------------|
| `static`               | exactly the declared `resources` + `max_actions` (no live discovery)         |
| `api`                  | discovered live from the backend (e.g. a GitHub App's installations + perms) |
| `api` + declared lists | **discovered ∩ declared** — the declared lists are a ceiling on discovery    |

When `discovery` is unset, the default is **type-aware**: backends that support live discovery
(`github-app`) default to `api`; those that don't (`artifactory`) are always `static`.

`discovery` only governs what the resolver's coverage check sees (and, later, what transparency
reports). It does not change mint-time behavior: a GitHub App still resolves installations when it
mints, regardless of mode.

## The `api` ceiling

Under `api`, declaring `resources`/`max_actions` caps discovery to that intersection:

- `max_actions` = the set intersection of discovered and declared actions.
- `resources` = each discovered resource kept only if the declared resource patterns permit it.

This is a safety bound: even if a GitHub App is installed on more than you intend, the realm
serves only what the ceiling allows. Example (`example/realms.d/github.yaml`):

```yaml
- realm: ghes-corp
  type: github-app
  capability:
    resources: [ "ghes-corp:acme/*" ]                 # ceiling on discovered repos
    max_actions: [ "contents:write", "actions:write" ]  # ceiling on discovered permissions
    refresh_interval: 15m                               # discovery cache TTL (api only)
  instances:
    - { name: gh-reader, app_id: 111111, private_key: ... }
```

## Static capability

A backend without live discovery (or any realm you want to pin) uses `static` and must declare
both lists (`example/realms.d/artifactory.yaml`):

```yaml
- realm: artifactory
  type: artifactory        # no api discovery -> static
  capability:
    resources: [ "artifactory:docker-local/*" ]
    max_actions: [ "write" ]
```

## Under `--dev`

`--dev` replaces every provider with an in-memory stub, so there is no backend to discover from.
The stub serves the declared `resources`/`max_actions`, which means:

- `static` and `api`-with-ceiling realms work locally and serve exactly the declared lists.
- A pure-`api` realm with **no** declared lists serves nothing under `--dev` (there is nothing to
  discover). Talmi logs a warning at startup; add a `resources`/`max_actions` ceiling to test that
  realm locally.

This is why `lease explain` (policy only) can succeed while `lease issue` fails under `--dev`: the
policy authorizes the request, but a pure-`api` realm's stub advertises no capability, so the
resolver finds no provider to mint from.

## Validation (`config vet`)

`config vet` reports (`CFG-REALM-CAP`):

- an invalid `discovery` value (must be `static` or `api`);
- `discovery: api` on a type that does not support it (e.g. `artifactory`);
- `static` without `resources` and `max_actions`;
- `refresh_interval` set while the effective mode is `static` (advisory warning; it is ignored).

Instance-level `capability` overrides the realm-level block and is validated the same way.

## Inspecting what providers serve

Three commands show the live picture so you don't have to work out discovery modes and ceilings by
hand. The `provider` commands hit admin endpoints and need a session that grants `talmi:providers`
(`read`); `lease explain` uses the token path.

`talmi provider list` shows every provider instance and its effective capability, computed the same
way the resolver computes it (discovery mode, then the ceiling). Each instance is a card so long
resource and action lists stay readable; a provider whose discovery is failing is still listed, with
its error, so one broken instance doesn't hide the rest:

```
$ talmi provider list
✓  gh-ci-reader  ghes-corp · github-app · api
    resources  ghes-corp:acme/*
               ghes-corp:beta/*
               ghes-corp:platform/*
  max actions  contents:read
               metadata:read

✗  gh-broken  ghes-corp · github-app · api
  error  discovery failed: 403 from api.github.example

✓  docker  artifactory · artifactory · static
    resources  artifactory:docker-local/*
  max actions  write
```

`talmi provider resolve <resource=actions>...` reports which provider would serve each request. It
does not mint. `--verbose` adds the candidate breakdown: which providers could serve it and, for
those that can't, why.

```
$ talmi provider resolve --verbose "ghes-corp:acme/x=contents:read"
✓  ghes-corp:acme/x = contents:read
       realm  ghes-corp
      chosen  gh-ci-reader
  candidates  ✓ gh-ci-reader
              ✗ gh-ci-writer  ceiling contents:write exceeds request (still covers)
```

`talmi lease explain` already prints the policy decision. It now also prints a **Would mint**
section: the least-privilege token split for the authorized requests, one entry per token with the
`resource=actions` it covers. This makes the `--dev` case above visible. When the policy authorizes
a request but no provider can serve it, explain prints the reason under **Would mint** instead of
implying that `lease issue` would succeed.

```
$ talmi lease explain --token "$OIDC" --resource "ghes-corp:acme/x=contents:read"
principal: alice (issuer gh-login)
  ✓ authorized · rules: dev-team
    ✓ ghes-corp:acme/x = [contents:read]

Would mint
  • gh-ro  ghes-corp:acme/x=contents:read
```

None of these mint a token, change policy state, or write a lease.
