# Background

Talmi builds on OIDC federation and short-lived tokens. If those are familiar, skip to
[How Talmi works](../concepts/index.md). If not, here is the short version, with links if you want the full detail.

## The problem: long-lived secrets

A personal access token or a service key in CI is a long-lived secret: it keeps working until someone rotates it, it is
hard to scope tightly, and it is hard to trace back to the job that leaked it. The goal is to get rid of it.

## The idea: verifiable identity, tokens on demand

Modern CI platforms can prove a job's identity without a stored secret. GitHub Actions, GitLab, and cloud providers mint
an **OIDC token** for each run: a short-lived, signed JWT whose claims say which repo, branch, and workflow it came
from. Anyone can verify it against the issuer's public keys, so no shared secret is involved. This is what "OIDC
federation" (or workload identity) means: a workload authenticates with a token another system vouches for, instead of a
credential it stores.

Talmi is the piece that turns that verified identity into access. A job presents its OIDC token and asks for a specific
resource. Talmi verifies the token, checks a policy, and mints a downstream token (a GitHub App installation token, an
Artifactory access token) scoped to exactly that resource, with a short expiry and a handle to revoke it early. Every
exchange is audited. This kind of service is a **security token service (STS)**.

The result: no long-lived provider secrets in your build systems, and every token traceable to the job and policy that
produced it.

## Read more

- [OpenID Connect, how it works](https://openid.net/developers/how-connect-works/)
- [JSON Web Token (RFC 7519)](https://www.rfc-editor.org/rfc/rfc7519)
- [OIDC for GitHub Actions](https://docs.github.com/en/actions/security-for-github-actions/security-hardening-your-deployments/about-security-hardening-with-openid-connect)

Then continue with [How Talmi works](../concepts/index.md) or run one in the
[Quickstart](../getting-started/quick-start.md).
