# AERF reference verifier — Go

> **Targets AERF v0.1.0-draft.1.** Public review draft, not yet stable.

A small (~200 line) Ed25519 signature verifier for AERF-EVIDENCE
receipts. Standard library only — no third-party Go dependencies.
Builds to a single static binary.

## What it does today

- Loads an Ed25519 public key from SPKI PEM (RFC 8410).
- Reads a receipt JSON file.
- Strips the `signature` and `timestamp` fields and re-canonicalizes
  the remaining payload using the same rules as the reference producer
  (sorted keys, compact separators, ASCII-escaped strings — see
  [SPEC.md §5.1](../../SPEC.md#51-canonical-json)).
- Verifies the Ed25519 signature against the canonical bytes.

## What it does NOT do yet

The following are described in [SPEC.md](../../SPEC.md) but are
**not** enforced by this v0.1.0-draft.1 reference verifier:

- Hash-chain verification (SPEC §8) — including Merkle root computation
  and the genesis-sentinel rule (locked decision C-6).
- RFC 3161 trusted timestamp verification (SPEC §11) — required for
  the production profile (locked decision C-11).
- JSON Schema conformance check against `schemas/aerf-v0.1.json`.

These will be added in subsequent drafts.

## Quick start

```bash
# Run directly (no install)
go run verify.go example/receipt.json example/public_key.pem

# Or build a static binary
go build -o aerf-verify verify.go
./aerf-verify example/receipt.json example/public_key.pem

# Confirm tamper detection
./aerf-verify example/receipt-tampered.json example/public_key.pem
# → exit code 1, "FAIL signature verification FAILED ..."
```

## Exit codes

| Code | Meaning |
|------|---------|
| `0`  | Signature valid. |
| `1`  | Signature invalid, or receipt malformed in a way that prevents verification. |
| `2`  | Usage error or I/O error (file not found, bad PEM, etc.). |

## Cross-compilation

```bash
GOOS=linux   GOARCH=amd64 go build -o aerf-verify-linux-amd64   verify.go
GOOS=linux   GOARCH=arm64 go build -o aerf-verify-linux-arm64   verify.go
GOOS=darwin  GOARCH=amd64 go build -o aerf-verify-darwin-amd64  verify.go
GOOS=darwin  GOARCH=arm64 go build -o aerf-verify-darwin-arm64  verify.go
GOOS=windows GOARCH=amd64 go build -o aerf-verify.exe           verify.go
```

Pre-built release binaries are deferred to v0.1.0-draft.2.

## Why Go

- **Single static binary distribution.** Auditors download one file
  and run it. Same playbook as Sigstore `cosign` and SLSA
  `slsa-verifier`.
- **Cross-compiles cleanly** to linux / macOS / windows × amd64 /
  arm64 from one source tree.
- **Standard library cryptography** (`crypto/ed25519`,
  `crypto/sha256`, `encoding/json`, `encoding/pem`) covers everything
  the verifier needs.
- **Reads in one sitting.** Auditors review the verifier itself,
  not just its output.

The reference *producer* of AERF receipts is the Python library
[`agentmint`](https://github.com/aniketh-maddipati/agentmint-python)
(`pip install agentmint`).

## Canonicalization compatibility

The verifier's canonical JSON output is byte-identical to the
producer's output of:

```python
json.dumps(d, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
```

This is the v0.1.0-draft.1 baseline (held decision C-4). Adoption of
full RFC 8785 JCS for v0.1.0 stable is under review.

## License

Apache 2.0 — see the repository [LICENSE](../../LICENSE).
