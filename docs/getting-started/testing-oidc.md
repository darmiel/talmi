# Testing with a mock OIDC issuer (flower)

To exercise Talmi's `oidc` issuer without a real identity provider, you can mint OIDC ID tokens with
arbitrary `sub` and claims using [flower](https://github.com/darmiel/flower), a small mock OIDC
issuer. A public instance is hosted at **`https://flower.d2a.io`**.

!!! warning "Testing only"
flower mints signed tokens for *any* subject with no authentication. Use it for local development
and testing, never as a real issuer.

## Mint a token

`POST /oidc/mint` with a JSON body:

```bash
curl -s -X POST https://flower.d2a.io/oidc/mint \
  -d '{
        "sub": "repo:acme/svc:ref:refs/heads/main",
        "aud": "talmi-dev",
        "claims": { "repository": "acme/svc", "ref": "refs/heads/main" },
        "expires_in": 600
      }' | jq -r .id_token
```

| Field        | Meaning                                                                 |
|--------------|-------------------------------------------------------------------------|
| `sub`        | Subject (required) - becomes the principal id.                          |
| `aud`        | Audience (required) - must match the issuer's `client_id` in Talmi.     |
| `claims`     | Extra claims merged into the token - these become principal attributes. |
| `expires_in` | Token lifetime in seconds (optional).                                   |

### A shell helper

A small zsh/bash function makes the common case a one-liner:

```bash
flower () {
  local aud="talmi-dev"
  local data; data=$(jq -n --arg aud "$aud" '.aud = $aud')
  for arg in "$@"; do
    key="${arg%%=*}"; value="${arg#*=}"
    data=$(jq --arg k "$key" --arg v "$value" '. + {($k): $v}' <<<"$data")
  done
  curl -s -X POST https://flower.d2a.io/oidc/mint -d "$data" | jq -r '.id_token'
}
```

```bash
flower sub=my-pipeline           # prints an ID token with sub=my-pipeline, aud=talmi-dev
```

The helper sets top-level fields (`sub`, `aud`, `expires_in`). For custom claims, use the raw
`curl` above with a `claims` object.

## Point Talmi at flower

Add an `oidc` issuer whose `issuer_url` is flower's issuer and whose `client_id` matches the `aud`
you mint with:

```yaml
# issuers.d/flower.yaml
- name: flower
  type: oidc
  issuer_url: https://flower.d2a.io/oidc   # must equal flower's configured issuer
  client_id: talmi-dev                     # must equal the token's aud
```

Talmi fetches discovery from `<issuer_url>/.well-known/openid-configuration` at startup, so the
server needs network access to flower. If verification fails on the issuer, confirm `issuer_url`
matches the `issuer` in
[
`https://flower.d2a.io/oidc/.well-known/openid-configuration`](https://flower.d2a.io/oidc/.well-known/openid-configuration).

## Issue against it

```bash
TOKEN=$(flower sub=my-pipeline)
talmi lease issue --issuer flower \
  --resource "github:acme/svc=contents:read" \
  --token "$TOKEN"
```

Add a rule matching `issuer: flower` (with a condition on the claims you mint) to authorize the
request - see [Rules](../configuration/rules.md).
