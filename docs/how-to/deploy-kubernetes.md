# Deploy to Kubernetes

Talmi is a single static binary in a distroless image. This guide runs it in Kubernetes with its config from a
ConfigMap, secrets from a Secret, PostgreSQL for persistence, and TLS at the edge.

## Before you begin

- A Kubernetes cluster and `kubectl` access.
- A container registry reachable from the cluster (the image is published to `ghcr.io/darmiel/talmi`).
- A PostgreSQL database if you want persistence. See [Run with PostgreSQL](postgres.md).
- Your bootstrap config and sourced tree ready, and credentials as secret material.

## Run the container

The image runs as a non-root user. Use the `server run` subcommand and point `--config` at the bootstrap file:

```bash
docker run --rm -p 8080:8080 \
  -v /etc/talmi:/etc/talmi:ro \
  ghcr.io/darmiel/talmi:latest server run --addr :8080 --config /etc/talmi/talmi.yaml
```

<!-- @formatter:off -->
!!! note "The command is `server run`"
    Run Talmi with `server run --addr ... --config ...`. There is no `serve` command.
<!-- @formatter:on -->

## Deployment and Service

Mount the bootstrap file and the sourced tree from a ConfigMap, and credentials from a Secret, referenced in config with
`file:`/`env:`. Probe `/healthz` for liveness and readiness.

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: talmi
spec:
  replicas: 1
  selector: { matchLabels: { app: talmi } }
  template:
    metadata: { labels: { app: talmi } }
    spec:
      containers:
        - name: talmi
          image: ghcr.io/darmiel/talmi:latest
          args: ["server", "run", "--addr", ":8080", "--config", "/etc/talmi/talmi.yaml"]
          ports: [ { containerPort: 8080 } ]
          envFrom:
            - secretRef: { name: talmi-secrets }   # DSNs, tokens as env: refs
          volumeMounts:
            - { name: config, mountPath: /etc/talmi, readOnly: true }
            - { name: keys,   mountPath: /run/secrets, readOnly: true }
          livenessProbe:  { httpGet: { path: /healthz, port: 8080 } }
          readinessProbe: { httpGet: { path: /healthz, port: 8080 } }
      volumes:
        - { name: config, configMap: { name: talmi-config } }
        - { name: keys,   secret: { secretName: talmi-keys } }
```

Put a TLS-terminating ingress or load balancer in front. Talmi speaks plaintext HTTP and expects TLS at the edge.

## Behind an ingress

The ingress is the TCP peer Talmi sees, so client-IP-based rate limiting must be told which peers to trust. Set
`rate_limit.trusted_proxies` to your ingress/pod CIDRs so Talmi reads the real client from
`X-Forwarded-For`. See [Configure rate limiting](rate-limiting.md).

## Persistence and migrations

Use the `postgres` store and auditor for anything beyond ephemeral runs. Talmi does not migrate the database; run
migrations as a Job before rolling out a version that needs a newer schema:

```yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: talmi-migrate
spec:
  template:
    spec:
      restartPolicy: Never
      containers:
        - name: migrate
          image: migrate/migrate:latest
          args: ["-path", "/migrations", "-database", "$(TALMI_STORE_DSN)", "up"]
          envFrom: [ { secretRef: { name: talmi-secrets } } ]
          volumeMounts: [ { name: migrations, mountPath: /migrations, readOnly: true } ]
      volumes:
        - { name: migrations, configMap: { name: talmi-migrations } }
```

See [Run with PostgreSQL](postgres.md) for the full store and audit setup.

## Multiple replicas

Running more than one replica has caveats today: scheduled tasks run on every replica, and a config webhook only reaches
the pod it hits. For rate limiting, use the `redis` backend so all replicas share one view
(see [Configure rate limiting](rate-limiting.md)). Coordinated multi-node operation is on the roadmap. Until then,
prefer a single replica, or rely on `sync.interval` for config convergence and accept duplicated background work.

## Verify

```bash
kubectl rollout status deploy/talmi
kubectl port-forward deploy/talmi 8080:8080 &
curl -sS localhost:8080/healthz
```

## Troubleshooting

- **CrashLoopBackOff at startup**: usually a config error or an unreachable database. Check
  `kubectl logs`; the server fails closed rather than starting misconfigured.
- **all clients share one rate-limit bucket**: `trusted_proxies` is unset, so every request looks like it came from the
  ingress IP. Set it to the ingress CIDR.
- **sessions break after a rollout**: the signing key is not stable across pods. Mount one
  `signing.key` from a Secret, not the `--dev` ephemeral key.

## Next steps

- [Run with PostgreSQL](postgres.md), [Configure rate limiting](rate-limiting.md).
- [Security overview](../security/index.md) for the public-exposure checklist.
