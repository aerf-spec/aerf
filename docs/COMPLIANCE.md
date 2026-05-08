# AERF Compliance Coverage

[← Back to README](../README.md)

AERF is an open evidence primitive for AI agent actions. It does not
replace full compliance programs. It specifically addresses the
*evidence layer* — tamper-evident, independently verifiable records of
what AI agents did and decided, what policy permitted each action, and
when it happened. A receipt plus a public key is a complete audit
artifact; verifying it requires no AERF software, account, or service
(see [SPEC.md §10](../SPEC.md#10-verification-procedure) and the
[Go reference verifier](../verifiers/go/verify.go)).

## What AERF covers

AERF satisfies controls requiring tamper-evident logs of AI agent
actions with cryptographic integrity guarantees. It does not address
input filtering, output safety, adversarial testing, data retention
policies, or failure planning controls.

## Framework Coverage Summary

| Framework | Domain | Primary Controls | Coverage | Page |
|---|---|---|---|---|
| AIUC-1 | AI agent governance | E015.4, E015.2, E015.1, D003.3, B006.2, B008.4 | Partial — evidence/logging layer only | [→](frameworks/AIUC-1.md) |
| HIPAA | Healthcare (ePHI) | 45 CFR §164.312(b) | Partial — audit controls technical safeguard | [→](frameworks/HIPAA.md) |
| SOC 2 | Security trust services | CC7.2, CC7.3 | Partial — monitoring and event evaluation | [→](frameworks/SOC2.md) |
| ISO/IEC 42001 | AI management system | 9.1, 10.2 | Partial — monitoring records and nonconformity evidence | [→](frameworks/ISO-42001.md) |
| EU AI Act | High-risk AI | Art. 12, Art. 19, Art. 17 | Partial — record-keeping and automatically generated logs | [→](frameworks/EU-AI-ACT.md) |
| NIST AI RMF | AI risk | GOVERN 1.4, MAP 2.2, MEASURE 2.8 | Partial — documentation and traceability | [→](frameworks/NIST-AI-RMF.md) |
| SR 11-7 | Model risk (banking) | Model inventory, audit trail | Partial — model output traceability | [→](frameworks/SR-11-7.md) |
| SOX 404 | Financial reporting controls | ITGCs (PCAOB AS 2201) | Partial — automated control evidence | [→](frameworks/SOX-404.md) |

In every row, *Partial* means AERF satisfies the cryptographic
integrity and independent-verifiability portion of the control. It
does not satisfy the surrounding programmatic, organizational, or
non-logging requirements.

## How to verify

The reference verifier is a single Go file using only the standard
library: [`verifiers/go/verify.go`](../verifiers/go/verify.go).

```bash
git clone https://github.com/aerf-spec/aerf.git
cd aerf/verifiers/go
go run verify.go example/receipt.json example/public_key.pem
# → "OK  receipt 7473e179..." and exit code 0

go run verify.go example/receipt-tampered.json example/public_key.pem
# → "FAIL signature verification FAILED ..." and exit code 1
```

The tampered file differs from the original by a single field
(`CLM-9920` → `CLM-9921`). The signature does not. See
[`verifiers/go/example/`](../verifiers/go/example/) for the full
artifact set including the SPKI PEM public key and the agentmint
evidence ZIP.

## Proposal: AERF as AIUC-1 E015 Reference Implementation

AIUC-1 E015.4 ([log model activity](https://www.aiuc-1.com/accountability/log-model-activity))
requires cryptographic hashing of log entries to ensure tamper-evidence
and independent verifiability. AERF provides a concrete open standard
for exactly this capability applied specifically to AI agent actions:
Ed25519-signed receipts (SPEC §7), SHA-256 chain hashing
(SPEC §8), and a single-binary verifier with no third-party
dependencies.

We propose co-authoring guidance with AIUC-1 contributors referencing
AERF as a named implementation option under E015.4 and E015.2,
alongside any other examples (WORM storage, third-party log management
platforms). AERF is the AI-agent-specific instantiation of the same
cryptographic-integrity principle.

Contact: open an issue at
[github.com/aerf-spec/aerf/issues](https://github.com/aerf-spec/aerf/issues)
or via [agentmint.run](https://agentmint.run).

---

[← Back to README](../README.md)
