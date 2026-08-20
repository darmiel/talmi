# Glossary

Short definitions of the terms used across these docs. Each links to the page that covers it in full.

Action
: A verb on a resource, like `contents:read` or `write`. A request pairs resources with actions; a [rule](rules.md)
grants them. See [Resources, actions, rules](../concepts/resources-actions-rules.md).

Artifact
: One minted downstream token inside a lease. A single request can produce several artifacts, one per provider.
See [Leases and revocation](../concepts/leases.md).

Bootstrap config
: The trusted, host-local `talmi.yaml` that Talmi reads at startup. Holds signing keys, store and audit settings, and
where the sourced tree comes from. See [Bootstrap](bootstrap.md).

Capability
: The ceiling of what a realm can ever hand out (its resources and maximum actions). A rule can only grant a subset.
See [Capabilities and discovery](../concepts/capabilities.md).

Condition
: The part of a rule that decides which principals it matches, using claim attributes (structured form or an `expr`
expression). See [Conditions](../concepts/conditions.md).

Issuer
: A verifier for a class of upstream tokens (an OIDC provider, GitHub OAuth, a signed Talmi session). It turns a token
into a principal. See [Issuers and principals](../concepts/issuers-and-principals.md).

Lease
: The record of one issuance: its artifacts, expiry, and a revocation secret. Revoking a lease invalidates its tokens
early. See [Leases and revocation](../concepts/leases.md).

Principal
: The verified identity produced by an issuer, an id plus a bag of claim attributes. Rules match on it.
See [Issuers and principals](../concepts/issuers-and-principals.md).

Provider
: The component that mints tokens for a realm by talking to the upstream (GitHub, Artifactory). One realm can have
several provider instances. See [Realms and providers](../concepts/realms-and-providers.md).

Realm
: A namespace for resources served by one kind of provider (for example a GitHub Enterprise host or an Artifactory
instance). See [Realms and providers](../concepts/realms-and-providers.md).

Resource
: The thing a caller wants access to, written `realm:path`, like `ghes-corp:acme/svc-a`. See
[Resources, actions, rules](../concepts/resources-actions-rules.md).

Revocation secret
: The handle returned with a lease that lets the caller revoke its tokens before they expire. See
[Leases and revocation](../concepts/leases.md).

Rule
: A policy entry: a `match` (which principals) plus `allow` statements (which resources and actions).
See [Resources, actions, rules](../concepts/resources-actions-rules.md).

`secret.Ref`
: A reference to a secret value rather than the value itself, using a scheme like `env:`, `file:`, or
`raw:`. See [Secrets](secrets.md).

Sourced config
: The issuers, realms, and rules tree, loaded from local files or a remote Git repository. A lower trust boundary than
the bootstrap file. See [Config sources](config-sources.md).

STS (security token service)
: A service that exchanges a verified identity for a scoped, short-lived token. Talmi is one. See
[Background](../introduction/background.md).
