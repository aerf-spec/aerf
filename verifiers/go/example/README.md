# Example artifacts — AERF v0.1.0-draft.1

This directory holds the canonical example used in the spec, the README,
and the verifier's own self-test.

| File | What it is |
|------|------------|
| `receipt.json`           | A real AERF-EVIDENCE receipt produced by the [`agentmint`](https://github.com/aniketh-maddipati/agentmint-python) reference library. Genesis receipt of its plan's chain. |
| `receipt-tampered.json`  | `receipt.json` with the `action` field changed from `submit:claim:CLM-9920` to `submit:claim:CLM-9921`. Demonstrates that any modification to a signed receipt invalidates the signature. |
| `public_key.pem`         | Ed25519 public key in SPKI PEM form (RFC 8410). |
| `evidence-package.zip`   | Full evidence package as exported by `agentmint`'s `Notary.export_evidence()` — includes the plan receipt, the same evidence receipt, the public key, FreeTSA CA certs, and the library's bundled OpenSSL / Python verification scripts. Use this when reviewing a complete end-to-end audit artifact. |

## Try it

```bash
# From the verifiers/go/ directory:
go run verify.go example/receipt.json example/public_key.pem
# → "OK  receipt 7473e179..." and exit 0

go run verify.go example/receipt-tampered.json example/public_key.pem
# → "FAIL signature verification FAILED ..." and exit 1
```

## Notes on this example

- **Self-reported timestamps.** This receipt was produced with
  `enable_timestamp=False` to keep the example deterministic and
  network-free. Production deployments **must** use RFC 3161 trusted
  timestamps per [SPEC.md §11](../../../SPEC.md#11-timestamp-anchoring)
  (locked decision C-11). The bundled `evidence-package.zip` contains
  RFC 3161 verification scripts but no live `.tsr` for this single
  receipt.
- **Genesis receipt.** The `previous_receipt_hash` field is omitted
  entirely (locked decision C-6). This is the genesis case — the
  first receipt of a plan's chain. The v0.1.0-draft.1 reference
  verifier does not yet enforce chain semantics; that work is
  scheduled for a later draft.
- **Field name `evidence_hash_sha512`.** The current reference
  producer hardcodes SHA-512 for the evidence hash and declares the
  algorithm via the field-name suffix. This satisfies locked
  decision C-3 (caller-specified hash algorithm per field). A
  registry-based form may be adopted in v0.1.0 stable; both will
  remain conformant during a deprecation cycle.
- **`aiuc_controls` field.** Deprecated per locked decision C-14;
  superseded by a generic `compliance_tags` array. The current
  producer still emits `aiuc_controls`; both fields are accepted by
  v0.1.0-draft.1 verifiers.
