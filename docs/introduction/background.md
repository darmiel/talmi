# Background

New to OIDC federation or short-lived tokens? This page covers the ideas Talmi builds on, with links out to the
canonical sources if you want to go deeper. If you already know what an STS and workload identity federation are, skip
to [How Talmi works](../concepts/index.md).

## Short-lived tokens vs. long-lived secrets

A long-lived secret is a credential that sits in a config file, a CI variable, or a `.env` and keeps working until
someone rotates it. A personal access token or a service account key is the common example. They are convenient and
dangerous: they are hard to scope tightly, hard to rotate without breaking things, and hard to trace back to the one job
that leaked one.

A short-lived token is minted at the moment it is needed, scoped to a single task, and expires on its own a few minutes
later. If it leaks, the blast radius is small and the window is short. The cost is that something has to mint it on
demand, from an identity the caller already has. That "something" is a token service.

## OIDC in one minute

OpenID Connect (OIDC) is a thin identity layer on top of OAuth 2.0. The piece that matters here is the **ID token**: a
JSON Web Token (JWT) that an issuer signs to assert "this is who the bearer is."
A JWT is three base64 segments (header, claims, signature). The claims include `iss` (which issuer minted it), `sub`
(the subject, the identity), `aud` (who it is meant for), and an expiry.

A verifier trusts an ID token by checking the signature against the issuer's public keys, which the issuer publishes at
a well-known JWKS endpoint, and by checking that `iss` and `aud` are the ones it expects. No shared secret is involved:
the verifier only needs the issuer's public keys.

See the [OpenID Connect overview](https://openid.net/developers/how-connect-works/) and
[RFC 7519](https://www.rfc-editor.org/rfc/rfc7519) (JWT) for the full picture.

## OIDC federation and workload identity

Federation means a workload proves its identity to one system using a token minted by another system that both sides
trust. A CI job does not store a secret for Talmi; it presents an OIDC token that its platform (GitHub Actions, GitLab,
a cloud provider) minted for that specific job. Talmi trusts the platform's signature, reads the claims, and decides
what the job is allowed to do.

This is the same model as cloud "workload identity federation." GitHub documents its side as
[OIDC hardening for GitHub Actions](https://docs.github.com/en/actions/security-for-github-actions/security-hardening-your-deployments/about-security-hardening-with-openid-connect).
The job's token is short-lived and scoped to the run, so there is no stored secret to leak.

## Where Talmi fits

Talmi is a **security token service (STS)**: it verifies an upstream identity and exchanges it for a scoped, short-lived
downstream token. A CI job presents its OIDC token and asks for access to a specific resource. Talmi verifies the token
against its issuer, checks a policy, mints a downstream token (a GitHub App installation token, a JFrog Artifactory
access token) scoped to exactly that resource, and returns it with an expiry and a handle to revoke it early. Every
exchange is audited.

The result: no long-lived provider secrets in your build systems, and every token traceable to the job and policy that
produced it. Continue with [How Talmi works](../concepts/index.md) for the model,
or [Quickstart](../getting-started/quick-start.md) to run one.
