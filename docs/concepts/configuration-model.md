# Configuration layout and trust model

Talmi's configuration is layered into a trusted bootstrap file and a lower-trust sourced tree.

## Bootstrap vs. sourced tree

The **bootstrap file** (`talmi.yaml`) is the trusted, host-local config: storage, signing, audit, admin auth, the config
`source`, and the include globs. It lives on the host you control.

The **sourced tree** is the issuers, realms, and rules. It can come from local files or a remote GitHub repository. Each
matched file is a YAML list of blocks, loaded in sorted path order:

```yaml
issuers: { include: [ "issuers.d/*.yaml" ] }   # list of issuer blocks
realms: { include: [ "realms.d/*.yaml" ] }    # list of realm blocks
rules: { include: [ "rules.d/*.yaml" ] }     # list of rules
```

Directory convention:

```
talmi.yaml
issuers.d/*.yaml
realms.d/*.yaml
rules.d/*.yaml
```

## Bootstrap sections

- **`store`** - `memory` or `postgres` (with a `dsn`). Holds the lease registry. See
  [Bootstrap](../reference/bootstrap.md).
- **`audit`** - `enabled`, `type` (`postgres`, `memory`, or `noop`), a `dsn`, optional `retention`
  and `sinks`. See [Auditing](../security/auditing.md).
- **`signing`** - the session signing key. See [Sessions and admin](../how-to/enable-admin-access.md).
- **`auth`** - enables the admin API.
- **`source`** - where the sourced tree comes from. See [Config sources](../reference/config-sources.md).

## Trust boundary

The bootstrap file is trusted. The sourced tree is **not**, which matters when it comes from a remote repository: a
sourced realm or issuer block can name arbitrary endpoints and reference the host's `file:`/`env:` secrets, which Talmi
resolves locally and then sends to whatever URL the block names. Anyone who can push to the config repo can rewrite
policy or exfiltrate host secrets.

Only source from a repository you fully control, restrict write access, and require review on the tracked branch.
The [Security](../security/trust-model.md) section covers this in full.

## Three validation layers

Talmi validates config in three independent places:

1. **`config vet`** - offline structural checks (and optional online provider probing). Run it in CI.
2. **Runtime** - on startup (non-dev) Talmi refuses to start on config errors.
3. **The engine** - at request time it denies anything the rules don't explicitly allow, even if the earlier checks were
   skipped.

See [Validation](../reference/validation.md).

## See also

- How-to: [Use a remote config source](../how-to/config-source-github.md)
- Reference: [Bootstrap](../reference/bootstrap.md), [Validation and config vet](../reference/validation.md)
- Security: [Config source trust](../security/trust-model.md)
