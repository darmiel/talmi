# Issuers and principals

## Issuer

An issuer is a trusted source of upstream identity. Rules match against the claims an issuer
produces. Four types exist:

- **`oidc`** - verifies an OIDC ID token against the issuer's discovery keys. Needs `issuer_url` and
  `client_id`. The principal id is the token `sub`; attributes are all claims. For airgapped or
  restricted networks you can supply keys directly instead of discovery - see
  [Configuration > Issuers](../reference/issuers.md).
- **`static`** - maps fixed token strings to attributes. Useful for local development and tests; the
  "token" the caller sends is literally the map key.
- **`github-oauth`** - verifies a GitHub / GHES OAuth access token by calling the GitHub API. The
  principal id is the login; attributes include `login`, `orgs`, and `teams` (as `org/slug`). This
  backs human admin login.
- **`talmi-session`** - verifies a session JWT that Talmi itself signed, used for admin API calls
  after `talmi session login`.

```yaml
- name: corp-oidc
  type: oidc
  issuer_url: https://issuer.example.com/
  client_id: talmi
```

For `oidc` with discovery, the server needs network access to the issuer's
`.well-known/openid-configuration` endpoint at startup to fetch signing keys.

## Principal

After verification the caller is represented as a principal: an `id`, the `issuer` that verified it,
and a bag of `attributes` (the claims). [Conditions](conditions.md) and expressions in rules evaluate
against these.

Both `issuer`/`iss` and `id`/`sub` are available in conditions. These identity keys are always taken
from the verified principal, never from token attributes - a token claim named `sub` cannot override
the verified subject. This is the anti-spoofing guarantee at the heart of the policy engine.

## See also

-
How-to: [GitHub Actions OIDC issuer](../how-to/github-actions-issuer.md), [generic OIDC issuer](../how-to/oidc-issuer.md), [enable admin access](../how-to/enable-admin-access.md)
- Reference: [Issuer types](../reference/issuers.md)
