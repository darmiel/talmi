# Validation

Talmi validates configuration in three layers (see
[Layout and trust model](../concepts/configuration-model.md#three-validation-layers)). The one you run yourself is
`config vet`.

## `config vet`

Checks the assembled tree and reports problems with source positions.

```bash
talmi config vet talmi.yaml            # offline structural checks
talmi config vet talmi.yaml --online   # also probe providers for capability/coverage
talmi config vet talmi.yaml --strict   # treat warnings as errors (good for CI)
talmi config vet talmi.yaml --json
talmi config vet talmi.yaml --local    # force local files, ignore a remote source
talmi config vet talmi.yaml --ref <sha>  # vet a specific commit of a GitHub source
```

- **Offline** checks structure: types, cross-references (a rule pointing at a known issuer/realm), duplicate names,
  pattern and action validity, capability blocks, and realm-name defaults/collisions.
- **`--online`** builds each provider and asks what resources it can serve, then flags rules that grant resources no
  working provider can actually mint.
- **`--strict`** turns warnings into a non-zero exit, so CI catches advisories too.

Findings carry a stable code (e.g. `CFG-XREF-REALM`, `CFG-REALM-CAP`) and a location, so you can act on them or filter
in `--json` output.

## JSON schema for editors

Generate JSON Schemas and point your YAML language server at them for as-you-type validation:

```bash
talmi config schema config  -o docs/schema/config.schema.json
talmi config schema issuers -o docs/schema/issuers.schema.json
talmi config schema realms  -o docs/schema/realms.schema.json
talmi config schema rules   -o docs/schema/rules.schema.json
```

Add a modeline to the top of a config file:

```yaml
# yaml-language-server: $schema=./docs/schema/config.schema.json
```

The committed schemas under `docs/schema/` are checked for drift in CI (`make schema-check`); run
`make schema` after changing a config type. See [Reference > JSON schema](json-schema.md).

## Runtime

On `server run` (non-dev), Talmi runs the offline checks and refuses to start on errors, then compiles rule expressions
and validates conditions once more. `--dev` skips this gate.
