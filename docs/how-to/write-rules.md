# Write and test policy rules

Rules are Talmi's policy: they decide which principals may request which resources and actions. Everything is denied
unless a rule allows it. This guide builds a rule from scratch and tests it without minting anything.

## Before you begin

- At least one [issuer](github-actions-issuer.md) and one provider ([GitHub App](github-app-provider.md)
  or [Artifactory](artifactory-provider.md)) configured.
- The [resources, actions, and rules model](../concepts/resources-actions-rules.md) and
  [conditions](../concepts/conditions.md) for background.

## What a rule looks like

A rule has a `match` (which principals it applies to) and a list of `allow` statements (which resources and actions it
grants). Rules live under `rules.d/`.

```yaml
- name: svc-a-read
  match:
    issuer: gh-actions          # the issuer this rule applies to
    condition:
      repository: "my-org/svc-a"  # match on principal attributes (token claims)
  allow:
    - resources: [ "ghes-corp:my-org/svc-a" ]
      actions: [ "contents:read" ]
```

Authorization unions the `allow` statements of every matching rule. A request is granted only if that union covers every
requested `resource=action`, and never beyond the realm's
[capability](../concepts/capabilities.md) ceiling. A request that is not fully covered is denied as a whole.

## 1. Start with a read-only rule

Grant one repository read access to one issuer, as above. Reload the config (restart, or let the sync interval pick it
up) and continue to testing.

## 2. Add a condition

A `condition` filters principals by their attributes. Use the short form for a single claim, or
`all` / `any` / `not` to combine them:

```yaml
  match:
    issuer: gh-actions
    condition:
      all:
        - repository: { in: [ "my-org/svc-a", "my-org/svc-b" ] }
        - ref: "refs/heads/main"
```

If you prefer an expression, use `expr` instead of `condition` (not both):

```yaml
  match:
    issuer: gh-actions
    expr: 'ctx.repository startsWith "my-org/" && ctx.ref == "refs/heads/main"'
```

A rule with no condition matches nobody unless you set `allow_empty: true`, which matches every principal from the
issuer. This is deny-by-default: an empty condition is treated as "match none," not
"match all."

## 3. Test with explain

`lease explain` runs verify and authorize and shows the decision, without minting or auditing:

```bash
talmi lease explain \
  --resource "ghes-corp:my-org/svc-a=contents:read" \
  --token "$OIDC" --issuer gh-actions
```

The output shows which rules matched and, per requested resource, whether it was covered and why. Use `--json` for the
full trace.

## 4. Validate the config

`config vet` catches structural problems before they reach the server: unknown issuers or realms in a rule, actions a
realm cannot grant, malformed conditions:

```bash
talmi config vet talmi.yaml --local
```

## Troubleshooting

- **Everything is denied**: no rule matches, or the condition is empty without `allow_empty`. Confirm the `issuer` name
  and the attribute names against `talmi token inspect "$OIDC"`.
- **`action ... is not valid for realm`**: the action does not exist for that realm kind. See the realm's action grammar
  in [Realm and provider types](../reference/realms.md).
- **Covered by policy but `no provider can serve`**: policy allows it but no provider serves that resource; check [
  `talmi provider list`](../reference/server.md).

## Next steps

- Reference: [Rules and conditions](../reference/rules.md), [Conditions](../concepts/conditions.md).
- [Enable admin access](enable-admin-access.md) uses rules with `talmi:*` resources.
