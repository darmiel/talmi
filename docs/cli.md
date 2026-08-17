# CLI reference

## Global flags

Apply to every command:

- `--server` (or `$TALMI_ADDR`) - target server address.
- `--log-level`, `--log-format` (`console`/`json`), `--no-color`.
- `--cli-config` - path to the CLI preferences file (default `$HOME/.talmi.yaml`).

Results go to **stdout** (so `--json | jq` is safe); logs, progress, and errors go to **stderr**.
Errors print a headline, hints, and the underlying cause, with a stable exit code: `2` usage,
`3` config, `4` auth, `5` denied.

## Commands

| Command                                   | What it does                                                                                                                                             |
|-------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------|
| `talmi server run`                        | Run the server. Flags: `-c/--config`, `--addr`, `--dev`, `--local`, `--ref`.                                                                             |
| `talmi lease issue [TOKEN]`               | Exchange an upstream token for resource tokens. `--resource` (repeatable), `--manifest`, `--out`, `--issuer`, `--json`.                                  |
| `talmi lease revoke`                      | Revoke a lease. `--from-lease`, or `--secret` + `--token id=value`; `-y/--yes` to skip the prompt.                                                       |
| `talmi lease explain [TOKEN]`             | Explain a decision (dry run). `--resource`, `--manifest`, `--issuer`, `--replay-id`, `--json`.                                                           |
| `talmi provider list`                     | List provider instances and their live effective capability (admin). `--json`.                                                                           |
| `talmi provider resolve <res=actions>...` | Preview which provider would serve a request (admin). `--verbose`, `--json`.                                                                             |
| `talmi session login`                     | Authenticate via GitHub device flow. `--with-token`.                                                                                                     |
| `talmi session status` / `logout`         | Show or clear the saved session. `--json` on `status`.                                                                                                   |
| `talmi audit list`                        | Query the audit log. `--limit`, `--action`, `--outcome`, `--principal`, `--request-id`, `--session-id`, `--fingerprint`, `--since`, `--until`, `--json`. |
| `talmi audit inspect <id>`                | Show one audit entry with its decision trace and artifacts. `--json`.                                                                                    |
| `talmi tasks list` / `trigger` / `logs`   | Inspect and run background tasks (admin).                                                                                                                |
| `talmi config vet [file]`                 | Validate config. `--online`, `--strict`, `--local`, `--ref`, `--json`.                                                                                   |
| `talmi config schema [target]`            | Emit JSON Schema for `config`, `issuers`, `realms`, or `rules`. `-o`.                                                                                    |
| `talmi token inspect JWT`                 | Print a JWT's claims without verifying it. `--json`.                                                                                                     |
| `talmi token fingerprint TOKEN`           | Compute a token fingerprint. `--type`, `-r/--raw`.                                                                                                       |
| `talmi version`                           | Show version/build info (local or from `--server`). `--json`.                                                                                            |
| `talmi completion <shell>`                | Generate a completion script (bash, zsh, fish, powershell).                                                                                              |

## Manifests

Instead of repeating `--resource`, list resources in a manifest file:

```yaml
# .talmi/access.yaml
resources:
  - resource: "ghes-corp:acme/svc-a"
    actions: [ "contents:write" ]
  - resource: "ghes-corp:acme/svc-b"
    actions: [ "contents:read" ]
```

```bash
talmi lease issue --manifest .talmi/access.yaml --token "$OIDC"
```

## Environment variables

- `$TALMI_ADDR` - default server address (same as `--server`).
- `$TALMI_TOKEN` - default upstream token for `lease issue`/`explain`.
