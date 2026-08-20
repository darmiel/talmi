# Talmi

![banner](docs/stylesheets/banner.svg)

Talmi is a short-lived token service (STS). It exchanges a verified upstream identity - a CI
pipeline's OIDC token, a human's GitHub login - for narrowly scoped, short-lived downstream tokens (a
GitHub App installation token, a JFrog Artifactory access token), and records every exchange in an
audit log.

Long-lived secrets in a build system are hard to rotate, hard to scope, and hard to audit. Talmi
replaces them with a request-time exchange: the caller proves who it is, Talmi checks a policy, mints
a token scoped to exactly what was asked for, and hands it back with an expiry and a revocation
handle.

## Documentation

**You can find the full documentation at <https://talmi.qwer.tz>**.

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
