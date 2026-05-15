# AGENTS.md

Guidance for AI coding agents and human contributors working in this repository.

## Project role

AERF is the Agent Evidence Receipt Format: an open, portable receipt format for cryptographic evidence of AI-agent actions. This repository is the specification and reference-verifier home, not the primary producer runtime.

Keep the boundary clear:

- This repo defines the wire format, schemas, examples, compliance mapping, and reference verifier behavior.
- `agentmint-python` is the reference producer/runtime that emits receipts.
- Do not add Python producer features here unless the repository structure explicitly changes.

## Stability expectations

This repo currently represents a public review draft. Treat the receipt shape, verifier semantics, and locked decisions as compatibility-sensitive.

Before changing normative behavior, read:

- `SPEC.md`
- `DECISIONS.md`
- `CHANGELOG.md`
- `schemas/aerf-v0.1.json`
- `verifiers/go/README.md`

If a change alters required fields, canonicalization, signature input, hash-chain rules, timestamp semantics, verifier acceptance, or compliance claims, update the spec, schema, examples, verifier docs, and changelog together.

## Repository map

- `README.md` — public overview and quickstart.
- `SPEC.md` — normative AERF-EVIDENCE draft specification.
- `DECISIONS.md` — locked and held design decisions.
- `docs/COMPLIANCE.md` — compliance navigation hub.
- `docs/frameworks/` — non-normative framework mappings.
- `schemas/aerf-v0.1.json` — JSON Schema for receipts.
- `verifiers/go/` — small standard-library Go reference verifier.
- `verifiers/go/example/` — canonical example receipts, key, and evidence package.

## Development rules

- Preserve AERF's core promise: small, boring, auditable, independently verifiable artifacts.
- Keep the Go verifier dependency-free unless there is a strong documented reason.
- Prefer explicit validation and deterministic behavior over clever abstractions.
- Do not introduce network calls, hosted-service dependencies, or hidden trust assumptions into verifier paths.
- Do not silently weaken verification failures. Invalid signatures, malformed required fields, unsupported algorithms, or tampered evidence must fail closed.
- Keep examples realistic but scrubbed. Never commit private keys, real patient data, customer data, credentials, API keys, or proprietary audit artifacts.
- Keep compliance pages precise about what AERF supplies and what remains outside AERF. Do not overclaim certification, legal compliance, or framework coverage.

## Validation

From the repository root, run the relevant checks before committing:

```bash
cd verifiers/go
go run verify.go example/receipt.json example/public_key.pem
go run verify.go example/receipt-tampered.json example/public_key.pem
```

Expected behavior:

- The valid receipt verifies successfully and exits 0.
- The tampered receipt fails verification and exits non-zero.

If Go tests are added later, run:

```bash
go test ./...
```

If the schema or sample receipts change, validate that examples still match the schema using the repository's documented validator or add one in the same PR.

## Spec and schema changes

For any receipt-format change:

1. Update `SPEC.md` first.
2. Update `schemas/aerf-v0.1.json` to match.
3. Update examples in `verifiers/go/example/`.
4. Update `verifiers/go/verify.go` if verifier behavior changes.
5. Update `README.md`, `CHANGELOG.md`, and `DECISIONS.md` if the public contract or design decisions changed.
6. Note any impact on `agentmint-python` compatibility.

Do not create undocumented compatibility gaps between the spec, schema, verifier, and examples.

## Cross-repo compatibility

When changing AERF behavior, check whether the producer in `aerf-spec/agentmint-python` must change. AgentMint operationalizes AERF; AERF should remain independently verifiable without AgentMint.

If this repo intentionally leads AgentMint, document the gap in `README.md`, `CHANGELOG.md`, or an issue so users understand which producer versions are compatible.

## Documentation style

- Use direct, concrete language.
- Distinguish normative requirements from non-normative examples and compliance mappings.
- Avoid marketing claims in `SPEC.md`.
- Prefer tables and checklists for reviewer-facing docs.
- Keep all version and draft labels consistent across files.

## Safe editing checklist

Before opening a PR or committing directly, confirm:

- [ ] Spec, schema, examples, and verifier remain aligned.
- [ ] Valid example verifies; tampered example fails.
- [ ] Compliance claims remain accurate and scoped.
- [ ] No secrets, private keys, or real regulated data were added.
- [ ] Cross-repo impact on `agentmint-python` is documented when relevant.
