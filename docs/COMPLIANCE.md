# AERF Compliance Coverage

[← README](../README.md)

AERF is an open evidence primitive for AI-agent actions. It does not
replace full compliance programs. It addresses the *evidence layer* —
tamper-evident, independently verifiable receipts of what AI agents
did and decided, what policy permitted each action, and when it
happened. A receipt plus a public key is a complete audit artifact;
verifying it requires no AERF software, account, or service (see
[SPEC.md §10](../SPEC.md#10-verification-procedure) and the
[Go reference verifier](../verifiers/go/verify.go)).

| Item | Value |
|---|---|
| AERF version | v0.1.0-draft.1 (May 2026) |
| Mappings sourced | 2026-05 |
| Last verified | 2026-05-08 |

## What AERF covers

AERF addresses controls requiring tamper-evident logs of AI-agent
actions with cryptographic integrity guarantees. AERF does not address
input filtering, output safety, adversarial testing, data retention
policies, or failure-planning controls.

## Framework Coverage Summary

The table below summarizes per-framework coverage. *Verifiable?*
indicates whether the listed controls are verifiable from a receipt
sample plus the issuer's public key alone.

| Framework | Version | Primary Controls | Coverage | Verifiable? | Page |
|---|---|---|---|---|---|
| AIUC-1 | published controls, sourced 2026-05 | E015.4, E015.2, E015.1, D003.3, B006.2, B008.4 | Partial | Yes | [→](frameworks/AIUC-1.md) |
| HIPAA | 45 CFR Part 164, current 2026-05 | §164.312(b) | Partial | Yes | [→](frameworks/HIPAA.md) |
| SOC 2 | 2017 TSC + 2022 points of focus | CC7.2, CC7.3 | Partial | Yes | [→](frameworks/SOC2.md) |
| ISO/IEC 42001 | :2023 | 9.1, 10.2 | Partial | Yes | [→](frameworks/ISO-42001.md) |
| EU AI Act | (EU) 2024/1689 | Art. 12, Art. 19, Art. 17 | Partial | Yes | [→](frameworks/EU-AI-ACT.md) |
| NIST AI RMF | 1.0 (NIST AI 100-1, 2023) | GOVERN 1.4, MAP 2.2, MEASURE 2.8 | Partial | Yes | [→](frameworks/NIST-AI-RMF.md) |
| SR 11-7 / SR 26-2 | SR 11-7 (2011); SR 26-2 (2026, excludes agentic AI) | Audit trail, model inventory linkage | Partial | Yes | [→](frameworks/SR-11-7.md) |
| SOX 404 | PCAOB AS 2201 | ITGCs (audit evidence, change management, logical access, computer operations) | Partial | Yes | [→](frameworks/SOX-404.md) |

In every row, *Partial* means AERF satisfies the cryptographic
integrity and independent-verifiability portion of the control. AERF
does not satisfy the surrounding programmatic, organizational, or
non-logging requirements. Per-control verdicts (including any *Full*
slices) are stated on each framework page.

## What "AERF-conformant" means for compliance use

For a deployment to use AERF as compliance evidence:

1. The producer issues AERF-EVIDENCE receipts per
   [SPEC §4](../SPEC.md#4-receipt-data-model).
2. Receipts are Ed25519-signed over the canonical JSON payload per
   [SPEC §5.1](../SPEC.md#51-canonical-json) and
   [§7](../SPEC.md#7-signing-procedure).
3. Per-plan SHA-256 chains are maintained on
   `previous_receipt_hash` per
   [SPEC §8](../SPEC.md#8-hash-chaining-locked-decision-c-5).
4. For the production profile, the signed payload is anchored with
   an RFC 3161 trusted timestamp per
   [SPEC §11](../SPEC.md#11-timestamp-anchoring-locked-decision-c-11).
5. The issuer's public key is published in SPKI PEM (RFC 8410) form
   per
   [SPEC §9.2](../SPEC.md#92-public-key-transport-held-decision-c-10).

An auditor confirms conformance by running the
[reference verifier](../verifiers/go/verify.go) against a sample of
receipts and the published public key.

## How to verify

```bash
git clone https://github.com/aerf-spec/aerf.git
cd aerf/verifiers/go
go run verify.go example/receipt.json example/public_key.pem
```

Expected output:

```text
OK  receipt 7473e179
    type:      notarised_evidence
    agent:     claims-agent
    action:    submit:claim:CLM-9920
    in_policy: true
    key_id:    c348d3c785c92249
```

Exit code: `0`.

```bash
go run verify.go example/receipt-tampered.json example/public_key.pem
```

Expected output:

```text
FAIL signature verification FAILED for receipt 7473e179
```

Exit code: `1`. The tampered file differs from the original by a
single character (`CLM-9920` → `CLM-9921`); the signature does not.
See [`verifiers/go/example/`](../verifiers/go/example/) for the full
artifact set including the SPKI PEM public key and the agentmint
evidence ZIP.

## Proposal: AERF as AIUC-1 E015 reference implementation

AIUC-1 E015.4 ([log model activity](https://www.aiuc-1.com/accountability/log-model-activity))
requires cryptographic hashing of log entries to ensure
tamper-evidence and independent verifiability. AERF provides a
concrete open standard for exactly this capability applied
specifically to AI-agent actions: Ed25519-signed receipts
([SPEC §7](../SPEC.md#7-signing-procedure)), SHA-256 chain hashing
([SPEC §8](../SPEC.md#8-hash-chaining-locked-decision-c-5)), and a
single-file standard-library verifier.

We propose co-authoring guidance with AIUC-1 contributors referencing
AERF as a named implementation option under E015.4 and E015.2,
alongside any other examples (WORM storage, third-party log
management platforms). AERF is the AI-agent-specific instantiation of
the same cryptographic-integrity principle. See the
[AERF × AIUC-1 page](frameworks/AIUC-1.md#proposal) for the concrete
asks.

Contact: open an issue at
[github.com/aerf-spec/aerf/issues](https://github.com/aerf-spec/aerf/issues),
or via [agentmint.run](https://agentmint.run).

---

[← README](../README.md)
