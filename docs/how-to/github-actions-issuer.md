# Set up a GitHub Actions OIDC issuer

Let GitHub Actions jobs authenticate to Talmi with their built-in OIDC token instead of a stored secret. After this, a
workflow can request a scoped token at runtime with no PAT in sight.

## Before you begin

- A running Talmi server you can edit the config for. See [Installation](../getting-started/installation.md).
- A GitHub repository or org whose Actions workflows will call Talmi.
- Familiarity with the [issuer model](../concepts/issuers-and-principals.md). If OIDC is new to you, read
  the [Background](../introduction/background.md) first.

## 1. Choose the issuer URL and audience

GitHub Actions signs its OIDC tokens with a fixed issuer:

```
https://token.actions.githubusercontent.com
```

The token's audience (`aud`) defaults to your repository owner URL, for example
`https://github.com/my-org`. You can override it per request in the workflow. Pick the value you will use as the
audience; Talmi enforces it as the token `aud`.

## 2. Add the issuer

Create `issuers.d/github-actions.yaml` in your sourced tree:

```yaml
- name: gh-actions
  type: oidc
  issuer_url: https://token.actions.githubusercontent.com
  client_id: https://github.com/my-org      # the audience you will request
```

Talmi fetches the issuer's discovery document and JWKS at startup, so it needs outbound access to
`token.actions.githubusercontent.com`. For restricted networks, see
[Set up a generic OIDC issuer](oidc-issuer.md#airgapped-and-restricted-networks).

## 3. Grant the workflow a rule

An issuer only proves identity; a [rule](write-rules.md) decides what that identity may request. The principal's
attributes are the token claims (`repository`, `ref`, `workflow`, and so on), so you can scope by repo or branch:

```yaml
- name: svc-a-ci
  match:
    issuer: gh-actions
    condition:
      repository: "my-org/svc-a"
  allow:
    - resources: [ "ghes-corp:my-org/svc-a" ]
      actions: [ "contents:read" ]
```

## 4. Request the token from a workflow

Give the job `id-token: write`, mint the OIDC token with the audience you configured, and send it as the bearer:

```yaml
permissions:
  id-token: write
  contents: read

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Get a scoped token from Talmi
        run: |
          OIDC=$(curl -sS "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=https://github.com/my-org" \
            -H "Authorization: Bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" | jq -r .value)
          curl -sS -X POST "$TALMI_URL/v2/token/issue" \
            -H "Authorization: Bearer $OIDC" \
            -H "Content-Type: application/json" \
            -d '{"resources":[{"resource":"ghes-corp:my-org/svc-a","actions":["contents:read"]}]}'
```

## Verify

Before wiring the workflow, dry-run the decision from your machine with a real OIDC token (or use
`config vet` to check the config):

```bash
talmi config vet talmi.yaml --local
talmi lease explain --resource "ghes-corp:my-org/svc-a=contents:read" --token "$OIDC" --issuer gh-actions
```

`explain` shows which rule matched and whether the request is authorized, without minting anything.

## Troubleshooting

- **`verification failed`**: the `aud` in the token does not match `client_id`, or `issuer_url` is wrong. Decode the
  token with `talmi token inspect "$OIDC"` and compare `iss` and `aud`.
- **`policy denied`**: no rule matches the principal. Check the `condition` against the token's
  `repository`/`ref` claims.
- **discovery fails at startup**: the server cannot reach the issuer. Use an inline JWKS, see
  [Set up a generic OIDC issuer](oidc-issuer.md#airgapped-and-restricted-networks).

## Next steps

- [Write and test policy rules](write-rules.md) to scope access precisely.
- [Set up a GitHub App provider](github-app-provider.md) so Talmi can mint the GitHub tokens.
