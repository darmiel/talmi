# Conditions

`match.condition` filters on principal attributes. The short form covers the common cases:

```yaml
condition:
  sub: { contains: "@company.com" }   # operator form
  team: platform                      # equality shorthand
```

Listing several keys means all of them must hold (AND). For explicit logic use `all`, `any`, and
`not`:

```yaml
condition:
  all:
    - user: { contains: "@company.com" }
    - not: { user: "bob@company.com" }   # sorry, Bob
```

## Operators

- `equals` - exact match (numbers are compared as floats).
- `contains` - substring for strings, membership for lists.
- `in` - the attribute's value is one of a list.
- `exists` - the attribute is present.

If an attribute name collides with an operator (`value`, `key`, `operator`, `all`, `any`, `not`), use
the long form:

```yaml
condition:
  key: in
  operator: equals
  value: some-value
```

## Expressions

For matching that conditions can't express, use `expr` instead of `condition` (one or the other, not
both). Expressions run in a sandbox with `ctx` (the principal's attributes) and `principal`
available; a runtime error or a non-boolean result is treated as no match (fail closed).

## Sharp edges

These are intentional and covered by tests:

- `not: { role: admin }` is **true when `role` is absent** - negation over a missing attribute
  matches.
- Numeric comparison coerces through `float64`, so integers above 2^53 can collide.
- An empty condition denies by default; `allow_empty: true` is required to match everyone from an
  issuer. A bare `condition: {}` does **not** match everyone unless `allow_empty` is set.

Attributes evaluate against the principal's `EvaluationContext`, where `iss`/`sub`/`id`/`issuer` are
always the server-derived values, never token claims of the same name.
