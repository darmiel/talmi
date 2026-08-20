# Enable admin access

Talmi's admin surface (audit queries, provider inspection, background tasks) is gated behind an authenticated session.
This guide sets up admin auth end to end: the GitHub OAuth App, the two issuers, the signing key, the `talmi` realm, the
admin rule, and logging in. Admins authenticate with their GitHub identity. Talmi verifies it once through a
`github-oauth`
issuer, then issues its own signed session JWT that a `talmi-session` issuer verifies on later calls. A rule grants the
`talmi:*` actions, exactly like any other resource.

Any issuer could back a session in principle. We use a GitHub OAuth App here because it carries the caller's org and
team membership as attributes, which lets you write the admin rule against a team rather than a list of usernames.

## Before you begin

- A running Talmi server you administer, with a sourced tree you can edit.
- Admin access to a GitHub org (to create the OAuth App and manage teams).
- The [sessions concept](../concepts/issuers-and-principals.md) and [rules](write-rules.md).

## 1. Create a GitHub OAuth App

In GitHub, go to **Settings > Developer settings > OAuth Apps > New OAuth App** (org-level for a shared App). Set:

- **Application name**: anything, for example `Talmi admin login`.
- **Homepage URL** and **Authorization callback URL**: any valid URL. The CLI logs in with the device flow, which does
  not redirect, so the callback is not used.

Create the App and copy its **Client ID**. You do not need a client secret for the device flow.

At login, admins consent to the `read:org` and `read:user` scopes so Talmi can read the org and team membership that
rules match on. You set these scopes in the `auth` block below.

## 2. Add the login and session issuers

Issuers live in the sourced tree, one file per concern. Add both to `issuers.d/admin.yaml`:

```yaml
# issuers.d/admin.yaml
- name: gh-login
  type: github-oauth
  server: https://github.com     # omit for github.com; set your GHES base for Enterprise

- name: talmi-session
  type: talmi-session
```

`github-oauth` verifies a GitHub access token by calling the GitHub API. The principal id is the login, and the
attributes include `login`, `orgs`, and `teams` (each as `org/slug`). That `teams`
attribute is what the admin rule in step 6 matches on. `talmi-session` verifies the session JWT that Talmi signs after
login.

## 3. Configure the signing key

Talmi signs session JWTs with the `signing` block in the **bootstrap file** (`talmi.yaml`), not the sourced tree.
`ES256` (an EC private key in PEM, via a [`secret.Ref`](../reference/secrets.md)) is the default and the right choice
for production. `HS256` takes a raw shared secret and is fine for local runs.

Generate an ES256 key with OpenSSL:

```bash
openssl ecparam -name prime256v1 -genkey -noout -out session-signing-key.pem
```

Then reference it from the bootstrap file:

```yaml
# talmi.yaml
signing:
  algorithm: ES256
  key: file:/run/secrets/session-signing-key.pem
```

Under `--dev` with no key, Talmi generates an ephemeral ES256 key at startup; sessions do not survive a restart.

## 4. Add the talmi realm

Admin resources live in the `talmi` realm (`talmi:audit`, `talmi:providers`, `talmi:tasks`,
`talmi:session`). Declare it in the sourced tree so those resources resolve. It has no external provider:

```yaml
# realms.d/talmi.yaml
- realm: talmi
  type: talmi
```

## 5. Enable the auth block

In the **bootstrap file** (`talmi.yaml`), name the login and session issuers and the OAuth App parameters the CLI needs.
Admin endpoints are enabled only when `auth` is present:

```yaml
# talmi.yaml
auth:
  login_issuer: gh-login
  session_issuer: talmi-session
  session_ttl: 8h
  server: https://github.com
  client_id: Iv1.xxxxxxxxxxxx     # the OAuth App client id from step 1
  scopes: [ read:org, read:user ]
```

## 6. Grant admins a rule

Admin access is a normal rule with `talmi:*` resources, in the sourced tree. Scope it to a GitHub team (the `teams`
attribute from step 2) so only its members can log in and act:

```yaml
# rules.d/admins.yaml
- name: talmi-admins
  match:
    issuer: gh-login
    condition:
      teams: { contains: "my-org/talmi-admins" }
  allow:
    - { resources: [ "talmi:session" ],   actions: [ "login" ] }
    - { resources: [ "talmi:audit" ],     actions: [ "read" ] }
    - { resources: [ "talmi:providers" ], actions: [ "read" ] }
    - { resources: [ "talmi:tasks", "talmi:tasks/*" ], actions: [ "read", "trigger" ] }
```

A session restores the original login issuer and its attributes, so this one rule authorizes both the interactive login
and the later admin API calls. `talmi` actions are exact strings with no ordering:
`read` does not imply `trigger`.

## 7. Log in

`talmi session login` runs the GitHub device flow, verifies your identity through `gh-login`, checks that a rule grants
you `talmi:session=login`, and stores the signed session:

```bash
talmi session login
talmi session status      # show the current server and session
talmi session logout      # clear the saved credential
```

## Using a personal access token instead

For automation, or where the interactive device flow is not an option, pass a GitHub token directly:

```bash
talmi session login --with-token "$GH_TOKEN"
```

A classic PAT with `read:org` and `read:user` works: Talmi verifies it through the same
`github-oauth` issuer and issues a session. It is a long-lived secret, though, and a downgrade from the device flow,
which never persists a GitHub credential. Prefer the device flow for humans and reserve `--with-token` for automation
that already manages a scoped token.

## Verify

```bash
talmi session status
talmi audit list --limit 5     # an authorized admin call
```

## Troubleshooting

- **`not authorized for this action`**: your identity does not satisfy the admin rule. Confirm your team membership
  matches the `teams` condition and that the `scopes` include `read:org`.
- **`invalid session token`**: the signing key changed or differs between replicas. Use a stable
  `signing.key`, not the `--dev` ephemeral key.
- **device flow blocked in CI**: use `--with-token` with a scoped PAT.

## Admin vocabulary

| Resource                       | Actions           |
|--------------------------------|-------------------|
| `talmi:session`                | `login`           |
| `talmi:audit`                  | `read`            |
| `talmi:providers`              | `read`            |
| `talmi:tasks`, `talmi:tasks/*` | `read`, `trigger` |

## Next steps

- [Auditing](../security/auditing.md) and the [audit events reference](../reference/audit-events.md).
- Reference: [Issuer types](../reference/issuers.md), [Bootstrap](../reference/bootstrap.md).
