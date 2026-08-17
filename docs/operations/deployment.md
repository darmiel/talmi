# Deployment

Talmi is a single static binary and ships as a distroless container image.

## Container

The `Dockerfile` builds a distroless image that runs as a non-root user. Mount your config and point
`--config` at the bootstrap file:

```bash
docker run --rm -p 8080:8080 \
  -v /etc/talmi:/etc/talmi:ro \
  talmi:latest server run --addr :8080 --config /etc/talmi/talmi.yaml
```

!!! warning "Container command"
Run Talmi with the `server run` subcommand (`server run --addr ... --config ...`). There is no
`serve` command.

## Kubernetes

A minimal Deployment. Mount the bootstrap file and the sourced tree from a ConfigMap (non-secret) and
credentials from a Secret (referenced with `file:`/`env:`).

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
            - secretRef: { name: talmi-secrets }
          volumeMounts:
            - { name: config, mountPath: /etc/talmi, readOnly: true }
            - { name: keys,   mountPath: /run/secrets, readOnly: true }
          livenessProbe:  { httpGet: { path: /healthz, port: 8080 } }
          readinessProbe: { httpGet: { path: /healthz, port: 8080 } }
      volumes:
        - { name: config, configMap: { name: talmi-config } }
        - { name: keys,   secret: { secretName: talmi-keys } }
```

Put a TLS-terminating ingress or load balancer in front - Talmi speaks plaintext HTTP and expects TLS
at the edge.

## Persistence and migrations

For anything beyond ephemeral local runs, use the `postgres` store and auditor. The application does
**not** auto-migrate the database; run migrations out of band from
`internal/store/postgres/migrations` (the repo uses `golang-migrate`):

```bash
migrate -path internal/store/postgres/migrations \
  -database "$TALMI_STORE_DSN" up
```

Run migrations before rolling out a new version that expects a newer schema.

## Multiple replicas

Running more than one replica today has caveats (scheduled tasks run on every replica; a config
webhook only reaches the pod it hit). Coordinated multi-node operation is on the roadmap. Until then,
prefer a single replica, or rely on the `sync.interval` for config convergence and accept duplicated
background work.
