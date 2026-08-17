# Config source trust boundary

The bootstrap file (`talmi.yaml`) is trusted: it lives on the host you control. The **sourced tree**
(issuers, realms, rules) is a lower trust boundary, and this is most important when it comes from a remote
GitHub repository.

## The risk

A sourced realm or issuer block can:

- name arbitrary provider or OAuth endpoints, and
- reference the host's local secrets through `file:`/`env:` refs, which Talmi resolves locally and
  then sends to whatever URL the block specifies.

So anyone who can push to the config repository (or the tracked branch) can either rewrite policy or
**exfiltrate host secrets** by pointing a client at an endpoint they control. Push access to the
config repo is effectively read access to every secret Talmi can resolve.

## The control

Until the code gates this (restricting schemes for remote trees, allow-listing endpoint hosts), the
control is organizational:

- Only source config from a repository you fully control.
- Restrict write access to that repository.
- Require review on the tracked branch (branch protection).
- Treat "can push to the config repo" as equal to "can read every Talmi secret".

## Reviewing changes before they land

`config vet` resolves a GitHub source the same way the server does, so you can validate a specific
commit before it merges:

```bash
talmi config vet talmi.yaml --ref <branch|tag|sha>
```

Run this in the config repo's CI (with `--strict`) so structural mistakes and unknown cross-references
fail the pull request. Combined with required reviews, that keeps a bad change from reaching the
tracked branch that the server pulls.

## Pinning

The server pins the sourced tree to a resolved commit SHA, so a running instance has a reproducible
view. A push triggers a reload (via webhook or `sync.interval`) to a new pinned commit.
