# JSON schema

Talmi generates JSON Schemas for each config surface so editors can validate config as you type.

## Generating

```bash
talmi config schema config  -o docs/schema/config.schema.json
talmi config schema issuers -o docs/schema/issuers.schema.json
talmi config schema realms  -o docs/schema/realms.schema.json
talmi config schema rules   -o docs/schema/rules.schema.json
```

Targets: `config` (the bootstrap file), `issuers`, `realms`, `rules` (the sourced blocks). Omit `-o`
to print to stdout.

## Editor integration

Add a modeline to the top of a config file so a YAML language server validates it:

```yaml
# yaml-language-server: $schema=./docs/schema/config.schema.json
```

Use the matching schema for each file kind (`issuers.schema.json` for `issuers.d/*.yaml`, etc.).

## Committed schemas and drift

The generated schemas live under `docs/schema/` and are committed. CI checks them for drift:

```bash
make schema         # regenerate all four
make schema-check   # fail if the committed schemas are stale
```

Run `make schema` whenever you change a config struct, and commit the result. Durations render as
strings (for example `"8h"`, `"90d"`); secret fields render as strings (a `secret.Ref`).
