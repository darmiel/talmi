# Leases and revocation

## Lease

`lease issue` returns a *lease*: the minted tokens, their expiry, and a revocation secret. A lease
groups every artifact minted for one request and stores the principal, matched policy names, config
revision, per-artifact metadata, expiry, and the revocation-secret hash. The token value itself is
never persisted.

Without `--out`, the CLI prints everything - including the token values and revocation secret - to
the terminal (shown once). Pass `--out` to write the full lease as JSON to a file instead:

```bash
talmi lease issue \
  --resource "ghes-corp:acme/svc-a=contents:write" \
  --token "$OIDC" \
  --out ./.talmi/lease.json
```

## Revocation

Revoke before expiry, either from the saved lease or by hand (`revoke` prompts for confirmation; pass
`--yes` to skip it):

```bash
talmi lease revoke --from-lease ./.talmi/lease.json
talmi lease revoke --secret "$SECRET" --token "<artifact-id>=<token-value>"
```

Revocation looks the lease up by the revocation secret (stored only as a SHA-256 hash), then revokes
each still-active revocable artifact through its provider. It is idempotent and resumable:
already-revoked artifacts are skipped, and a partial failure leaves the rest active for a retry.

Some providers (GitHub) require the original token value to revoke it, so `--from-lease` carries the
token values from the saved file; by-value artifacts need `--token id=value` if you revoke by hand.

## Fingerprints

Depending on the provider, Talmi records a SHA-256 *fingerprint* of each minted token in the audit
log (never the token itself). If a downstream system shows activity by a leaked token, the
fingerprint traces it back to the issuing request and lease. See
[Auditing](../operations/auditing.md).
