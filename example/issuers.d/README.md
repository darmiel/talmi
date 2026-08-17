# `issuers.d/`: trusted identity sources

Files here define **issuers**: the upstream systems Talmi trusts to prove *who
the caller is*. On an `issue`/`why`/`login` request Talmi picks an issuer,
verifies the presented token with it, and turns the result into a **principal**
(`id`, `issuer`, and a bag of `attributes`). Rules (see [`../rules.d/`](../rules.d))
then match against that principal.

Each `*.yaml` file is a **list** of issuer blocks. All matched files are merged
(sorted by path), so split them however reads best. Each block needs a unique
`name` and a `type`.

```yaml
- name: my-issuer      # referenced by rules' match.issuer and by auth.*
  type: oidc           # oidc | static | github-oauth | talmi-session
  # ...type-specific fields...
```

## Types

### `oidc`
Verifies an OIDC ID token against the issuer's discovery keys (signature,
issuer, audience, expiry). The principal `id` is the token `sub`, and `attributes`
are all claims.

```yaml
- name: corp-oidc
  type: oidc
  issuer_url: https://token.actions.githubusercontent.com   # required
  client_id:  https://github.com/my-org                     # required (audience)
```

> The server fetches `<issuer_url>/.well-known/openid-configuration` at startup,
> so it needs network access to the issuer.

#### Airgapped / restricted networks

When the discovery or JWKS endpoint is unreachable, supply the verification keys
instead. Two mutually-exclusive options (both keep `issuer_url` required and still
enforce it as the token's `iss`):

```yaml
# Fully offline: inline the JWKS JSON (a secret.Ref; mount a file with file:).
- name: corp-oidc
  type: oidc
  issuer_url: https://token.actions.githubusercontent.com
  client_id: https://github.com/my-org
  jwks: file:/run/secrets/corp-oidc.jwks.json   # no discovery, no network fetch

# Or point at a reachable internal JWKS mirror: discovery is skipped, keys are
# still fetched from this URL (so they rotate).
- name: corp-oidc
  type: oidc
  issuer_url: https://token.actions.githubusercontent.com
  client_id: https://github.com/my-org
  jwks_url: https://jwks-mirror.internal/corp/jwks.json
```

Setting both `jwks` and `jwks_url` is a config error. Inline `jwks` keys are
pinned: rotate them by updating the source and reloading. The JWKS is
public-key material (not a secret to protect), and inline keys are strictly safer
than discovery since an attacker on the network can't swap them.

### `static`
Maps fixed token strings to attributes. Local dev and tests only: the
"token" the client sends is literally the map key.

```yaml
- name: dev-ci
  type: static
  token_map:
    dev-token-123:          # <- this string is the token
      sub: dev-pipeline
      team: platform
```

### `github-oauth`
Verifies a GitHub / GHES OAuth access token by calling the GitHub API. The
principal `id` is the login. `attributes` include `login`, `orgs`, and `teams`
(each as `org/slug`). This is what backs human admin login.

```yaml
- name: gh-login
  type: github-oauth
  server: https://github.com     # optional; omit for github.com, set for GHES
```

### `talmi-session`
Verifies a session JWT that Talmi itself signed (after `talmi login`). Used for
admin API calls.

```yaml
- name: talmi-session
  type: talmi-session
```

> A verified session **restores the original login issuer and attributes**, so
> admin rules are written against the *login* issuer (e.g. `gh-login`), not
> `talmi-session`. The `talmi-session` issuer only needs to exist and be named
> in `auth.session_issuer`.

## Notes

- **Auto-discovery vs. explicit.** If the client doesn't name an issuer, Talmi
  auto-detects: a JWT (`eyJ...`) is routed by its `iss` claim to the matching
  `oidc` issuer, and anything else is looked up as a `static` token. Callers can
  also force an issuer explicitly (`--issuer`, or the `issuer` field in the request).
- **Every issuer should be referenced** by a rule's `match.issuer` or by
  `auth.login_issuer` / `auth.session_issuer`. `talmi config vet` warns about
  unused issuers.
- Signing for `talmi-session` is configured in the bootstrap `signing:` block,
  not here.
