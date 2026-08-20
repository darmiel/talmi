# Realms and providers


A *realm* is a namespace of resources with its own meaning of "resource" and "action". A *provider*
is the backend that actually mints tokens for a realm. A realm block's `type` picks the backend, and
everything a realm can ever hand out is bounded by its *capability*.

This page covers the model. For the config fields (what each provider block looks like, which keys are required),
see [Configuration > Realms and providers](../reference/realms.md).


## Provider types


Talmi ships three realm types. They differ in what they mint and in how their capability ceiling is
determined:


- **`github-app`** mints GitHub App installation tokens. Its capability is *discovered live* from the
  App: Talmi queries the installations, repos, and permissions the App actually has, and the declared
  lists narrow that down. A resource is an `<owner>/<repo>` and actions are `<permission>:<level>`.
- **`artifactory`** mints JFrog Artifactory access tokens. Its capability is *declarative*: the token
  is scoped to configured groups, so what you declare is the ceiling. A resource is a repository path
  and actions are bare levels (`read < annotate < write`).
- **`talmi`** is the session realm. It has no backend and mints nothing. It exists so the admin
  resources (`talmi:session`, `talmi:audit`, `talmi:providers`, `talmi:tasks`) have semantics that
  rules can grant.


The [Resources, actions, and rules](resources-actions-rules.md) page has the full action grammar for
each type.


## Realms, instances, and capability


A realm can hold several `instances`, one per App or server. Each instance carries its own
credentials but serves the same realm namespace. Capability is the ceiling of what the realm may ever
hand out (which resources, up to which action level); an instance can tighten it further.

The grant a caller actually gets is always the overlap of two things: the policy (the union of
matching [rules](resources-actions-rules.md)) and the realm's [capability](capabilities.md). A rule
can never grant more than the realm can mint, and the realm can never mint more than its backend
allows. See [Capabilities and discovery](capabilities.md) for how the effective ceiling is computed
from a static declaration versus live discovery.


## Least-privileged selection


When several instances in a realm can serve a resource, the resolver picks the one whose action
ceiling most tightly fits the request (then by resource breadth, then declaration order). That is why
you can run a read-only App and a write App in the same realm: a read request goes to the read-only
App, and the write App is only reached when a write is actually asked for.

## See also

-
How-to: [GitHub App provider](../how-to/github-app-provider.md), [Artifactory provider](../how-to/artifactory-provider.md)
- Concepts: [Capabilities and discovery](capabilities.md)
- Reference: [Realm and provider types](../reference/realms.md)
