# Installation

Talmi is a single Go binary. The same binary is both the server (`talmi server run`) and the client
CLI (`talmi lease`, `talmi config`, ...).

## Prerequisites

- To run a prebuilt binary or container: nothing beyond the host.
- To build from source: Go 1.26 or newer.
- For a production deployment with persistence: a PostgreSQL database (optional; the default store is
  in-memory).

## Install with `go install`

```bash
go install github.com/darmiel/talmi@latest
```

This puts the `talmi` binary in `$(go env GOPATH)/bin`. Make sure that directory is on your `PATH`.

## Build from source

```bash
git clone https://github.com/darmiel/talmi
cd talmi
make install        # go install with version/commit stamped in
```

`make install` embeds the version and commit into the binary so `talmi version` reports them.

## Container image

The repository ships a `Dockerfile` that builds a distroless image running as a non-root user.

```bash
docker build -t talmi:local .
docker run --rm -p 8080:8080 \
  -v "$PWD/example:/etc/talmi:ro" \
  talmi:local server run --addr :8080 --config /etc/talmi/talmi.dev.yaml
```

Mount your config directory read-only and point `--config` at the bootstrap file inside it. See
[Deployment](../how-to/deploy-kubernetes.md) for Kubernetes.

## Verify

```bash
talmi version
talmi --help
```

## Next

Continue with the [Quick start](quick-start.md) to run a server and issue your first token.
