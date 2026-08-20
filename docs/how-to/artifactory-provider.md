# Set up an Artifactory provider

Let Talmi mint short-lived JFrog Artifactory access tokens, so a build can push or pull artifacts without a long-lived
Artifactory key.

<!-- @formatter:off -->
!!! warning "Experimental, not priority-supported"
    The Artifactory provider is not a priority right now and should be treated as testing-only. Minted
    tokens are group-scoped rather than scoped to the exact request (see the caveat below), and the
    provider has known gaps. Use it to evaluate Talmi, not for production access, until this changes.
<!-- @formatter:on -->

## Before you begin

- A running Talmi server. See [Installation](../getting-started/installation.md).
- An Artifactory instance and an admin token that can mint access tokens.
- The group (s) the minted tokens should carry.
- An issuer for your callers, for example [GitHub Actions OIDC](github-actions-issuer.md).

## 1. Create an admin token in Artifactory

In Artifactory, create an access token for a user or service account that has permission to mint tokens for the groups
you will hand out. Treat it as a high-value secret; it is the credential Talmi uses to mint every downstream token for
this realm.

## 2. Store the admin token as a secret

Mount it and reference it as a `secret.Ref` (`env:` or `file:`; `raw:` for local testing).
See [Secrets](../reference/secrets.md):

```
env:TALMI_ARTIFACTORY_ADMIN_TOKEN
```

## 3. Add the realm and provider instance

Create `realms.d/artifactory.yaml`:

```yaml
- realm: artifactory
  type: artifactory
  capability:
    discovery: static
    resources: [ "artifactory:docker-local/*" ]
    max_actions: [ "write" ]
  instances:
    - name: art-main
      base_url: https://artifactory.example.com
      admin_token: env:TALMI_ARTIFACTORY_ADMIN_TOKEN
      groups: [ "ci-writers" ]
```

<!-- @formatter:off -->
!!! warning "Scope caveat"
    The current Artifactory provider scopes minted tokens to the configured `groups`, not to the
    exact resource and action requested. Talmi's authorization gate still limits what a caller may
    request, but the credential itself is group-scoped. Choose `groups` as tightly as your
    Artifactory permission model allows.
<!-- @formatter:on -->

## 4. Grant a rule

```yaml
- name: push-images
  match:
    issuer: gh-actions
    condition:
      repository: "my-org/svc-a"
  allow:
    - resources: [ "artifactory:docker-local/team-a" ]
      actions: [ "write" ]
```

## Verify

```bash
talmi config vet talmi.yaml --local
talmi provider list
talmi lease issue --resource "artifactory:docker-local/team-a=write" \
  --token "$OIDC" --issuer gh-actions
```

## Troubleshooting

- **`provider list` shows an error**: the `base_url` is wrong or the admin token cannot mint tokens.
- **`artifactory instance requires at least one 'group'`**: set `groups`.
- **minted token has more access than expected**: that is the group-scoping caveat above; narrow the group in
  Artifactory.

## Next steps

- [Write and test policy rules](write-rules.md).
- Reference: [Realm and provider types](../reference/realms.md).
