# Secrets

Talmi never takes inline secret values in config. Any credential - a signing key, a database DSN, a provider token, an
OIDC JWKS - is a `secret.Ref`: a scheme-prefixed string that Talmi resolves at load time.

## Schemes

| Ref           | Resolves to                                      |
|---------------|--------------------------------------------------|
| `raw:VALUE`   | the literal `VALUE`. For local development only. |
| `file:/PATH`  | the contents of the file at `/PATH`.             |
| `env:VARNAME` | the value of the environment variable `VARNAME`. |

```yaml
signing:
  key: file:/run/secrets/session-signing-key.pem

store:
  dsn: env:TALMI_STORE_DSN

# in a realm instance
private_key: file:/run/secrets/gh-app.pem
```

## Handling

- Secrets are resolved where they are consumed and are never logged. Error messages reference the scheme or variable
  name, not the value.
- In Kubernetes, mount secrets as files (`file:`) or inject them as env vars (`env:`) from a Secret; avoid `raw:`
  outside local runs.

## Trust boundary caveat

`secret.Ref`s in the sourced tree resolve against the host, so a sourced issuer/realm block can reference host `file:`/
`env:` secrets and send them to any endpoint it names. Only source config from a repository you control.
See [Security > Config source trust](../security/trust-model.md).
