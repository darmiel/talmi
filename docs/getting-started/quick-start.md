# Quick start

This walks through a minimal, working setup: one issuer, one realm, one rule, then issuing a token.
A complete example tree lives in [`example/`](https://github.com/darmiel/talmi/tree/main/example).

## 1. Bootstrap file

The bootstrap file (`talmi.yaml`) is the trusted, host-local config. It configures storage, signing,
and points at three sectioned directories for issuers, realms, and rules.

```yaml
# talmi.yaml
store: { type: memory }
audit: { enabled: false }

signing:
  algorithm: HS256
  key: raw:change-me          # dev only; see Configuration > Secrets for real keys

issuers: { include: [ "issuers.d/*.yaml" ] }
realms: { include: [ "realms.d/*.yaml" ] }
rules: { include: [ "rules.d/*.yaml" ] }
```

## 2. An issuer

The issuer verifies the caller's upstream token. For local development, a `static` issuer maps fixed
token strings to attributes - the "token" the caller sends is literally the map key.

```yaml
# issuers.d/ci.yaml
- name: dev-ci
  type: static
  token_map:
    dev-token-123:
      sub: dev-pipeline
      team: platform
```

## 3. A realm

A realm is a namespace of resources and the provider instances that mint tokens for it. `capability`
is the ceiling of what the realm may ever hand out.

```yaml
# realms.d/gh.yaml
- realm: ghes-corp
  type: github-app
  capability:
    resources: [ "ghes-corp:acme/*" ]
    max_actions: [ "contents:read", "contents:write" ]
  instances:
    - name: gh-dev
      app_id: 12345
      private_key: file:/run/secrets/gh-app.pem
```

## 4. A rule

A rule grants access to principals from an issuer. This one lets anything from `dev-ci` read
`acme/*` repositories. `allow_empty: true` means the rule matches every principal from that issuer
(no condition required).

```yaml
# rules.d/dev.yaml
- name: dev-allow
  match:
    issuer: dev-ci
    allow_empty: true
  allow:
    - resources: [ "ghes-corp:acme/*" ]
      actions: [ "contents:read" ]
```

## 5. Validate and run

```bash
talmi config vet talmi.yaml          # catches structural mistakes before startup
talmi server run --config talmi.yaml --addr :8080
```

While iterating, run with `--dev` to replace every real provider with an in-memory stub that returns
dummy tokens. That lets you exercise policy and leases without any GitHub or Artifactory credentials:

```bash
talmi server run --config talmi.yaml --dev
```

## 6. Issue a token

For a real deployment the token comes from your OIDC provider. With the `static` issuer above, the
"token" is just the map key:

```bash
talmi lease issue --resource "ghes-corp:acme/svc-a=contents:read" --token dev-token-123
```

Without `--out`, the command prints the minted token and the revocation secret to the terminal
(shown once). Pass `--out ./lease.json` to write the full lease to a file instead.

## 7. Explain a decision

To see *why* a request would be allowed or denied without minting anything:

```bash
talmi lease explain --resource "ghes-corp:acme/svc-a=contents:write" --token dev-token-123
```

`explain` shows the policy decision per request and, when authorized, the least-privilege token that
*would* be minted.

## Next

- Understand the pieces: [Concepts](../concepts/index.md).
- Configure real issuers and providers: [Configuration](../configuration/layout.md).
- Run it for real: [Operations](../operations/server.md).
