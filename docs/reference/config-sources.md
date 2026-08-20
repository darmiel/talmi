# Config sources

The sourced tree (issuers, realms, rules) comes either from local files or a GitHub repository.

## Local files

The default. The bootstrap file's include globs read from disk, sorted by path for determinism:

```yaml
issuers: { include: [ "issuers.d/*.yaml" ] }
realms: { include: [ "realms.d/*.yaml" ] }
rules: { include: [ "rules.d/*.yaml" ] }
```

## GitHub repository

Instead of local files, Talmi can read the tree from a GitHub repository, pinned to a commit for reproducibility.
Configure a `source.github` block with a GitHub App that can read the repo:

```yaml
source:
  github:
    server: https://github.example.com/   # omit for github.com
    owner: my-org
    repo: talmi-config
    ref: main                            # branch, tag, or sha
    path: ""                              # subdirectory, if any
    app_id: 1815
    installation_id: 25508
    private_key: file:/run/secrets/config-source.pem
    webhook_secret: env:TALMI_WEBHOOK_SECRET        # enables the reload webhook
  sync:
    interval: 8h   # periodically re-pull the tree
```

The repository follows the same convention as local files: `issuers.d/`, `realms.d/`, `rules.d/`
(under `path` if set). Talmi resolves the `ref` to a commit SHA and fetches the tree at that commit.

### Setting up the GitHub source

1. Create a GitHub App with **Contents: read** on the config repository (and **Webhooks** if you want push-triggered
   reloads). Install it on the repo and note the App ID and installation ID.
2. Store the App private key as a secret and reference it with `private_key: file:...`.
3. Point `source.github` at the repo and `ref`.
4. (Optional) Set `webhook_secret` and configure a repository webhook to
   `POST /v2/webhooks/github` so a push reloads the running config. Otherwise `sync.interval`
   re-pulls periodically.

`server run` and `config vet` resolve the source the same way. Pass `--local` to force local files, or
`--ref <branch|tag|sha>` to vet a specific commit before it merges.

## Reload

Config reloads atomically: a new snapshot is built off to the side, and only a successful build is swapped in. A failed
reload leaves the running config untouched. Reloads are triggered at startup, by the `sync.interval`, and by the GitHub
webhook.
