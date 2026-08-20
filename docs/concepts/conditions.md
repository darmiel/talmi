# Conditions

`match.condition` filters on principal attributes. The short form covers the common cases:

```yaml
condition:
  sub: { contains: "@company.com" }   # operator form
  team: platform                      # equality shorthand
```

Listing several keys means all of them must hold (AND). For explicit logic use `all`, `any`, and
`not`, and nest them as deeply as you need:

```yaml
condition:
  all:
    - user: { contains: "@company.com" }
    - not: { user: "bob@company.com" }   # sorry, Bob
    - any:
        - team: platform
        - team: sre
```

That matches a company user who is not Bob and is on either the platform or the SRE team.

## Operators

- `equals` - exact match (numbers are compared as floats).
- `contains` - substring for strings, membership for lists.
- `in` - the attribute's value is one of a list.
- `exists` - the attribute is present.

If an attribute name collides with an operator (`value`, `key`, `operator`, `all`, `any`, `not`), use the long form:

```yaml
condition:
  key: in
  operator: equals
  value: some-value
```

## Expressions

For matching that conditions cannot express, use `expr` instead of `condition` (one or the other, not both). An
expression is written in [expr](https://expr-lang.org/) and must return a boolean. Two values are in scope:

- `ctx` - the principal's attributes as a map, with the identity keys (`iss`, `sub`, `id`, `issuer`)
  always set to the server-verified values.
- `principal` - the principal itself.

```yaml
# a single claim
expr: 'ctx.ref == "refs/heads/main"'

# combine several, with string and membership operators
expr: 'ctx.repository startsWith "acme/" && ctx.ref == "refs/heads/main"'

# membership against a list attribute
expr: '"acme/platform" in ctx.teams'

# guard against a missing attribute
expr: 'ctx.env == "prod" && ("deployer" in (ctx.roles ?? []))'
```

A runtime error or a non-boolean result is treated as no match, so a typo fails closed rather than matching everyone.

## Gotchas

These are intentional and covered by tests:

- `not: { role: admin }` is **true when `role` is absent** - negation over a missing attribute matches.
- Numeric comparison coerces through `float64`, so integers above 2^53 can collide.
- An empty condition denies by default; `allow_empty: true` is required to match everyone from an issuer. A bare
  `condition: {}` does **not** match everyone unless `allow_empty` is set.

Attributes evaluate against the principal's `EvaluationContext`, where `iss`/`sub`/`id`/`issuer` are always the
server-derived values, never token claims of the same name.

## See also

- How-to: [Write and test policy rules](../how-to/write-rules.md)
- Reference: [Rules and conditions](../reference/rules.md)
