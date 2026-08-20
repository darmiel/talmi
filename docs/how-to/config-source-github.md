# Use a remote config source

By default Talmi reads its issuers, realms, and rules from local files. You can instead load that tree from a GitHub
repository, pinned to a commit, so policy changes go through pull requests and review.

## Before you begin

- A running Talmi server you administer.
- A GitHub repository to hold the config tree, with tightly controlled write access.
- Admin access to create a GitHub App that can read that repository.
- Read the [config source trust model](../security/trust-model.md) first. The sourced tree is a lower trust boundary
  than the host, and whoever can push to it can rewrite your policy.

<!-- @formatter:off -->
!!! warning "Treat push access as secret access"
    A sourced block can reference the server's local `file:`/`env:` secrets and name any URL to send
    them to. Anyone who can push to the tracked branch can rewrite policy or exfiltrate host secrets.
    Require reviews on the branch you track and restrict who can push.
<!-- @formatter:on -->

## 1. Lay out the repository

Use the same convention as local files: `issuers.d/`, `realms.d/`, `rules.d/` (under a subdirectory if you set `path`).

## 2. Create a GitHub App that can read the repo

Create a GitHub App with **Contents: Read-only** on the config repository. If you want push-triggered reloads, also
enable webhooks. Install it on the repo and note the **App ID** and **installation ID**. Generate a private key and
store it as a secret (see [Secrets](../reference/secrets.md)).

## 3. Point the bootstrap at the source

```yaml
source:
  github:
    server: https://github.example.com/   # omit for github.com
    owner: my-org
    repo: talmi-config
    ref: main                              # branch, tag, or sha
    path: ""                                # subdirectory, if any
    app_id: 1815
    installation_id: 25508
    private_key: file:/run/secrets/config-source.pem
    webhook_secret: env:TALMI_WEBHOOK_SECRET   # enables POST /v2/webhooks/github
  sync:
    interval: 8h                            # periodically re-pull
```

Talmi resolves `ref` to a commit SHA and fetches the tree at that commit.

## 4. Set up reloads

Config reloads atomically: a new snapshot is built off to the side and swapped in only if it builds cleanly, so a bad
push never takes down the running config. Reloads happen at startup, on the
`sync.interval`, and, if you set `webhook_secret`, when a repository webhook posts to
`/v2/webhooks/github`.

## Verify

Vet a specific commit before it merges, and confirm the running config against the source:

```bash
talmi config vet --ref pr-branch          # vet the tree at a branch/tag/sha
talmi config vet talmi.yaml --local        # force local files, ignore the remote source
```

## Troubleshooting

- **startup fails resolving the source**: the App cannot read the repo, or `owner`/`repo`/`ref` is wrong. Confirm the
  installation and permissions.
- **a push did not reload**: the webhook is not configured or `webhook_secret` is unset; the
  `sync.interval` still re-pulls on its schedule.
- **a bad config merged**: the running config is unchanged because the reload failed to build; fix the tree and push
  again.

## Next steps

- Reference: [Config sources](../reference/config-sources.md).
- [Config source trust model](../security/trust-model.md).
