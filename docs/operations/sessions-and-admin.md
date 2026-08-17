# Sessions and admin access

Audit, task, and provider-inspection commands require an authenticated admin session.

## Signing

Talmi signs admin session JWTs with the key in the bootstrap `signing` block. `ES256` is the default
and expects an EC private key in PEM (via a `secret.Ref`). `HS256` uses a raw shared secret, which is
fine for local runs. The algorithm is pinned on verify, so there is no algorithm-confusion or
`alg=none` attack.

```yaml
signing:
  algorithm: ES256
  key: file:/run/secrets/session-signing-key.pem
```

Under `--dev` with no key configured, Talmi generates an ephemeral ES256 key at startup (sessions
won't survive a restart).

## Enabling the admin API

Set the bootstrap `auth` block, naming a `github-oauth` `login_issuer` and a `talmi-session`
`session_issuer`:

```yaml
auth:
  login_issuer: gh-login
  session_issuer: talmi-session
  session_ttl: 8h
  server: https://github.com
  client_id: Iv1.xxxxxxxx
  scopes: [ read:org ]
```

Admin endpoints are enabled only when `auth` is present. Each is guarded per-handler: it verifies the
session and authorizes a `talmi:*` action, so adding a protected route means remembering to guard it.

## Logging in

`talmi session login` runs a GitHub device flow, verifies your identity through the `login_issuer`,
and stores a session JWT signed by the server. Your GitHub identity still has to satisfy a rule
granting `talmi:session=login`:

```bash
talmi session login
talmi session login --with-token "$GH_TOKEN"   # skip the device flow
talmi session status                           # show the current server + session
talmi session logout                           # clear the saved credential
```

The rule that admits you (and grants further admin actions) looks like:

```yaml
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

A session restores the original login issuer and its attributes, so the same rule authorizes both the
interactive login and subsequent admin API calls.

## Admin vocabulary

| Resource                       | Actions           |
|--------------------------------|-------------------|
| `talmi:session`                | `login`           |
| `talmi:audit`                  | `read`            |
| `talmi:providers`              | `read`            |
| `talmi:tasks`, `talmi:tasks/*` | `read`, `trigger` |
