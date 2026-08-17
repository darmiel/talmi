# Talmi

Talmi is a short-lived token service (STS). It exchanges a verified upstream identity - a CI
pipeline's OIDC token, a human's GitHub login - for narrowly scoped, short-lived downstream tokens (a
GitHub App installation token, a JFrog Artifactory access token), and records every exchange in an
audit log.

Long-lived secrets in a build system are hard to rotate, hard to scope, and hard to audit. Talmi
replaces them with a request-time exchange: the caller proves who it is, Talmi checks a policy, mints
a token scoped to exactly what was asked for, and hands it back with an expiry and a revocation
handle.

## Documentation

Full documentation lives at **<https://darmiel.github.io/talmi/>** (built from `docs/`):

- [Installation](docs/getting-started/installation.md) and
  [Quick start](docs/getting-started/quick-start.md)
- [Concepts](docs/concepts/index.md) - the mental model
- [Configuration](docs/configuration/layout.md) - issuers, realms, rules, sources, secrets
- [Operations](docs/operations/server.md) - running, deploying, sessions, auditing
- [Security](docs/security/index.md) - the trust model
- [CLI reference](docs/cli.md)

## Quick start

```bash
go install github.com/darmiel/talmi@latest

# a minimal config tree lives in example/
talmi config vet talmi.yaml
talmi server run --config talmi.yaml --dev        # --dev stubs providers, no creds needed
talmi lease issue --resource "ghes-corp:acme/svc-a=contents:read" --token dev-token-123
```

See the [Quick start](docs/getting-started/quick-start.md) for the full walkthrough.

## Building the docs locally

```bash
pip install mkdocs-material
mkdocs serve
```

## Contributing

Internal architecture, invariants, and the security-critical paths are documented in
[CONTRIBUTING.md](CONTRIBUTING.md).
