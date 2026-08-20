# Set up a generic OIDC issuer

Verify OIDC ID tokens from any compliant provider (a cloud IdP, GitLab, Keycloak, another CI platform). Talmi checks the
signature against the issuer's keys and turns the token into a principal.

## Before you begin

- A running Talmi server. See [Installation](../getting-started/installation.md).
- The provider's issuer URL and the audience it mints tokens for.
- If OIDC is unfamiliar, read the [Background](../introduction/background.md).

For GitHub Actions specifically, use [Set up a GitHub Actions OIDC issuer](github-actions-issuer.md), which is the same
issuer type with the values filled in.

## 1. Add the issuer

The principal id is the token's `sub`; every claim becomes an attribute rules can match on. Create
`issuers.d/my-idp.yaml`:

```yaml
- name: my-idp
  type: oidc
  issuer_url: https://idp.example.com      # must equal the token 'iss'
  client_id: talmi                          # the token 'aud'
```

By default Talmi fetches `<issuer_url>/.well-known/openid-configuration` at startup, then the JWKS it points to, so the
server needs outbound access to the issuer. Keys are refreshed as they rotate.

## 2. Grant a rule and verify

Add a [rule](write-rules.md) that matches this issuer, then dry-run a decision with a real token:

```bash
talmi config vet talmi.yaml --local
talmi lease explain --resource "ghes-corp:acme/svc-a=contents:read" --token "$TOKEN" --issuer my-idp
```

## Airgapped and restricted networks

When discovery or the JWKS endpoint is unreachable, supply the verification keys instead. The two options are mutually
exclusive, and both still require `issuer_url` and enforce it as the token `iss`.

Inline the JWKS (fully offline). The keys are pinned; rotate them by updating the source and reloading:

```yaml
- name: my-idp
  type: oidc
  issuer_url: https://idp.example.com
  client_id: talmi
  jwks: file:/run/secrets/my-idp.jwks.json   # no discovery, no network fetch
```

Or point at a reachable JWKS mirror. Discovery is skipped, but keys are still fetched from this URL, so they rotate:

```yaml
- name: my-idp
  type: oidc
  issuer_url: https://idp.example.com
  client_id: talmi
  jwks_url: https://jwks-mirror.internal/my-idp/jwks.json
```

Pinned keys are strictly safer than discovery: an attacker on the network cannot swap them. The JWKS is public-key
material, so it is fine to commit an inline `jwks` file reference (not the private key).

## Troubleshooting

- **`'jwks' and 'jwks_url' are mutually exclusive`**: set only one.
- **`verification failed`**: `iss`/`aud` mismatch, or the signing key is not in the JWKS. Inspect the token with
  `talmi token inspect "$TOKEN"`.
- **startup hangs or errors fetching keys**: the issuer is unreachable; switch to inline `jwks` or a
  `jwks_url` mirror.

## Next steps

- [Write and test policy rules](write-rules.md).
- Reference: [Issuer types](../reference/issuers.md).
