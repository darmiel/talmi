# Set up a GitHub App provider

Let Talmi mint short-lived GitHub App installation tokens scoped to specific repositories. This backs resources in a
`github-app` realm, so a CI job can read or write a repo without a stored PAT.

## Before you begin

- A running Talmi server. See [Installation](../getting-started/installation.md).
- Admin access to the GitHub org (or GHES instance) that owns the repositories.
- An issuer already set up for your callers, for example
  [GitHub Actions OIDC](github-actions-issuer.md).
- The [realms and providers model](../concepts/realms-and-providers.md) and
  [capabilities](../concepts/capabilities.md) for background.

## 1. Create a GitHub App

In GitHub, go to **Settings > Developer settings > GitHub Apps > New GitHub App** (org-level for a shared App). Set:

- **Name** and **Homepage URL** (any valid URL).
- **Webhook**: uncheck **Active**; Talmi does not need App webhooks here.
- **Repository permissions**: grant only what your resources need. For read access to file contents, set **Contents:
  Read-only**. Add others (for example **Contents: Read and write**, **Pull requests**) as your policy requires. These
  permissions are the hard ceiling on what any token from this App can do.

Create the App.

## 2. Generate a private key and install the App

- On the App page, under **Private keys**, click **Generate a private key**. A `.pem` downloads.
- Under **Install App**, install it on the org and select the repositories Talmi should serve. Note the **App ID** (App
  settings) and, if you need it, the installation.

## 3. Store the private key as a secret

Mount the `.pem` where the server can read it and reference it, never inline. See [Secrets](../reference/secrets.md).

```
file:/run/secrets/gh-app.pem
```

## 4. Add the realm and provider instance

Create `realms.d/ghes-corp.yaml`. The instance config keys (`app_id`, `private_key`, `server`) are inline under the
instance:

```yaml
- realm: ghes-corp
  type: github-app
  capability:
    discovery: api                 # api = discover repos from the App; static = list them here
  instances:
    - name: gh-corp
      app_id: 123456
      private_key: file:/run/secrets/gh-app.pem
      server: https://github.example.com   # omit for github.com
```

With `discovery: api`, Talmi asks the App which repositories it can serve and derives the capability ceiling from the
App's installed permissions. With `discovery: static`, you declare the ceiling yourself:

```yaml
  capability:
    discovery: static
    resources: [ "ghes-corp:my-org/*" ]
    max_actions: [ "contents:write" ]
```

See [Capabilities and discovery](../concepts/capabilities.md) for how the effective ceiling is computed.

## 5. Grant a rule

A [rule](write-rules.md) grants a subset of the realm's capability to a set of principals:

```yaml
- name: svc-a-read
  match:
    issuer: gh-actions
    condition:
      repository: "my-org/svc-a"
  allow:
    - resources: [ "ghes-corp:my-org/svc-a" ]
      actions: [ "contents:read" ]
```

## Verify

```bash
talmi config vet talmi.yaml --local
talmi provider list                     # shows the instance and its live effective capability
talmi lease issue --resource "ghes-corp:my-org/svc-a=contents:read" --token "$OIDC" --issuer gh-actions
```

The lease response carries a `ghs_...` installation token scoped to that repo, with an expiry.

## Troubleshooting

- **`provider list` shows an error for the instance**: the App ID or private key is wrong, or the App is not installed.
  Re-check the `.pem` and installation.
- **`no provider can serve`**: the requested repo is outside the App's installation (api discovery)
  or your declared `resources` (static).
- **minted token cannot write**: the App's repository permission is read-only. Raise it in the App settings; the App
  permission is the ceiling.

## Next steps

- [Write and test policy rules](write-rules.md).
- Reference: [Realm and provider types](../reference/realms.md).
