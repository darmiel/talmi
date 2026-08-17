# Issuers

Issuers verify the caller's upstream token. Each block lives under `issuers.d/`. See
[Concepts > Issuers](../concepts/issuers-and-principals.md) for the model.

## `oidc`

Verifies an OIDC ID token. The principal id is `sub`; attributes are all claims.

```yaml
- name: gh-actions
  type: oidc
  issuer_url: https://token.actions.githubusercontent.com   # required
  client_id:  https://github.com/my-org                     # required (audience)
```

By default the server fetches `<issuer_url>/.well-known/openid-configuration` at startup, so it needs
network access to the issuer.

### Airgapped / restricted networks

When discovery or the JWKS endpoint is unreachable, supply the verification keys instead. Two
mutually-exclusive options (both keep `issuer_url` required and still enforce it as the token `iss`):

```yaml
# Fully offline: inline the JWKS JSON (a secret.Ref; mount a file with file:).
- name: gh-actions
  type: oidc
  issuer_url: https://token.actions.githubusercontent.com
  client_id: https://github.com/my-org
  jwks: file:/run/secrets/gh-actions.jwks.json   # no discovery, no network fetch

# Or point at a reachable internal JWKS mirror: discovery is skipped, keys are
# still fetched from this URL (so they rotate).
- name: gh-actions
  type: oidc
  issuer_url: https://token.actions.githubusercontent.com
  client_id: https://github.com/my-org
  jwks_url: https://jwks-mirror.internal/gh/jwks.json
```

Setting both `jwks` and `jwks_url` is an error. Inline `jwks` keys are pinned - rotate them by
updating the source and reloading. The JWKS is public-key material, and pinned keys are strictly
safer than discovery (an attacker on the network cannot swap them).

## `static`

Maps fixed token strings to attributes. Local development and tests only: the "token" the client
sends is literally the map key.

```yaml
- name: dev-ci
  type: static
  token_map:
    dev-token-123: { sub: dev-pipeline, team: platform }
```

## `github-oauth`

Verifies a GitHub / GHES OAuth access token by calling the GitHub API. Backs human admin login. The
principal id is the login; attributes include `login`, `orgs`, and `teams` (as `org/slug`).

```yaml
- name: gh-login
  type: github-oauth
  server: https://github.com     # omit for github.com
```

## `talmi-session`

Verifies a session JWT that Talmi signed (after `talmi session login`). Used for admin API calls.

```yaml
- name: talmi-session
  type: talmi-session
```

The signing key is configured in the bootstrap [`signing`](bootstrap.md) block, not here.
