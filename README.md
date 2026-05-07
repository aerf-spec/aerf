# AERF — Agent Evidence Receipt Format

**`v0.1.0-draft.1` — Public Review Draft, May 2026. Not yet stable.**

AERF is an open wire format for **cryptographic receipts of AI-agent
actions**. Each receipt is an Ed25519-signed JSON document that records
*what* an agent did, *what policy* permitted it, *when* it happened,
and the *full evidence* of the action. Receipts are independently
verifiable — no AERF software, account, or service is needed to check
one. The reference verifier in this repo is a single Go file using only
the standard library.

This repository is the home of the specification and a reference
verifier. The reference *producer* lives in
[`agentmint-python`](https://github.com/aniketh-maddipati/agentmint-python)
(`pip install agentmint`).

> AERF is to agentic AI evidence what `cosign` is to container images
> and `slsa-verifier` is to build provenance: a small, boring, auditable
> file format with a small, boring, auditable verifier.

## Sample receipt

```json
{
  "id": "7473e179-001c-4d3b-94bc-d0f53dd6eec6",
  "type": "notarised_evidence",
  "plan_id": "bc023208-ea24-410a-a280-ff36820e18a6",
  "agent": "claims-agent",
  "action": "submit:claim:CLM-9920",
  "in_policy": true,
  "policy_reason": "matched scope submit:claim:*",
  "evidence_hash_sha512": "b35d8ba27ad113c4...bb39e30c",
  "evidence": { "...": "..." },
  "observed_at": "2026-05-06T16:22:33.490443+00:00",
  "policy_hash": "260eca8ac43ae65e...985d6bf1",
  "key_id": "c348d3c785c92249",
  "plan_signature": "3e5b83e83b77bfa2...dea8ee01",
  "signature": "8bd989a95ab60863...04e97208"
}
```

> *`evidence` field abbreviated for display; see
> [`verifiers/go/example/receipt.json`](verifiers/go/example/receipt.json)
> for the full file. `evidence_hash_sha512`, `policy_hash`,
> `plan_signature`, and `signature` truncated.*

The `signature` is an Ed25519 signature over the canonical JSON
encoding of the receipt with `signature` and `timestamp` removed.
A receipt by itself plus an issuer's public key is a complete audit
artifact.

## Try it

```bash
git clone https://github.com/aerf-spec/aerf.git
cd aerf/verifiers/go
go run verify.go example/receipt.json example/public_key.pem
# → "OK  receipt 7473e179..." and exit code 0

# Confirm tamper detection
go run verify.go example/receipt-tampered.json example/public_key.pem
# → "FAIL signature verification FAILED ..." and exit code 1
```

The tampered file differs from the original by a single field
(`CLM-9920` → `CLM-9921`). The signature does not.

## What's in this repo

```
.
├── README.md                          You are here.
├── SPEC.md                            The AERF-EVIDENCE specification (draft).
├── DECISIONS.md                       Locked + held design decisions C-1..C-20.
├── CHANGELOG.md
├── LICENSE                            Apache 2.0 — code, schemas, examples.
├── LICENSE-spec                       CC BY 4.0 — prose / specification text.
├── schemas/
│   └── aerf-v0.1.json                 JSON Schema (Draft 2020-12) for the
│                                      EVIDENCE receipt shape.
└── verifiers/
    └── go/
        ├── verify.go                  ~200 lines, stdlib only.
        ├── go.mod
        ├── README.md
        └── example/
            ├── receipt.json
            ├── receipt-tampered.json
            ├── public_key.pem
            └── evidence-package.zip   Full agentmint evidence ZIP.
```

## What's NOT in v0.1.0-draft.1

These are intentionally deferred. They will land in subsequent drafts:

- **Test vectors** — a directory of ~8 conformance vectors (genesis,
  chain, tamper, replay, malformed, etc.).
- **Python and TypeScript reference verifiers.** Today, Python is the
  reference *producer*; only the Go verifier ships in this repo.
- **`compliance/`** — mappings from AERF fields to AIUC-1, NIST AI RMF,
  EU AI Act, ISO/IEC 42001, etc.
- **Governance, contributing, and security policy documents.**
- **CI workflows and pre-built release binaries** of the verifier.
- **AERF-AUTHZ profile** — the spec acknowledges it as a future
  profile (held decision C-17) but does not specify it. v0.1 ships
  the EVIDENCE profile only.
- **Reference verifier hash-chain and RFC 3161 timestamp checks.**
  Both are described normatively in the spec; the Go reference
  verifier in this draft enforces signatures only. See
  [`verifiers/go/README.md`](verifiers/go/README.md).

## Status and stability

This is a **public review draft**. The wire format may change before
v0.1.0 stable. Locked decisions (see [DECISIONS.md](./DECISIONS.md))
are binding for v0.1.0; held decisions remain open until v0.1.0 stable.
We tag every page header and the spec title page accordingly so
nothing here gets cited as final.

## Reference implementation

- **Producer:** [`agentmint-python`](https://github.com/aniketh-maddipati/agentmint-python) — `pip install agentmint`
- **Verifier:** This repo, [`verifiers/go/`](verifiers/go/)

The reference producer at the time of this draft (`agentmint` 0.1.x)
diverges from the spec on two locked decisions (genesis sentinel C-6
and chain hash input C-7). The v0.1.0-draft.1 example is a single
genesis receipt to sidestep the gap; library fixes are tracked in
[issue #2](https://github.com/aerf-spec/aerf/issues/2) for v0.1.0-draft.2.

Insurance carriers can use Plan receipts as machine-readable
underwriting intake and Evidence receipts as tamper-evident claims
evidence. See Appendix B.

## License

Dual-licensed:

- **Prose** (SPEC, README, DECISIONS, CHANGELOG) — Creative Commons
  Attribution 4.0 International ([`LICENSE-spec`](./LICENSE-spec)).
- **Code, schemas, example artifacts** (verifiers, schemas,
  receipt.json, etc.) — Apache License 2.0 ([`LICENSE`](./LICENSE)).

If a file's license is unclear, the per-directory `README.md` or the
file's own header governs.

## Editor

Aniketh Maddipati ([agentmint.run](https://agentmint.run)).
Issues and PRs welcome.
