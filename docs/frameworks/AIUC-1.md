# AERF × AIUC-1

[← Back to Compliance Overview](../COMPLIANCE.md) · [← Back to README](../../README.md)

AIUC-1 is the AI Usage Controls standard (six domains: A. Data &
Privacy, B. Security, C. Safety, D. Reliability, E. Accountability,
F. Society). The full evidence list is published at
[aiuc-1.com/evidence](https://www.aiuc-1.com/evidence).

This page maps AERF receipts (see [SPEC.md §4](../../SPEC.md#4-receipt-data-model))
to AIUC-1 controls. AERF is in scope for the **evidence/logging
layer**. It is out of scope for adversarial testing, output safety,
input filtering, and policy/programmatic controls.

## Primary mappings

### E015.4 — Log integrity protection
Source: [aiuc-1.com/accountability/log-model-activity](https://www.aiuc-1.com/accountability/log-model-activity)

- **Requirement.** Logs of AI system activity are tamper-evident and
  independently verifiable through cryptographic hashing or equivalent
  integrity protections.
- **AERF provides.** Every receipt is signed with Ed25519 (RFC 8032)
  over the canonical JSON payload (SPEC [§5.1](../../SPEC.md#51-canonical-json),
  [§7](../../SPEC.md#7-signing-procedure)). Receipts within a plan
  chain via SHA-256 of the previous canonical payload (SPEC
  [§8](../../SPEC.md#8-hash-chaining-locked-decision-c-5)).
- **Coverage.** **Full** for the cryptographic integrity portion of
  the control. AERF does not provision storage, retention, or access
  control for log archives — those remain customer responsibilities.
- **Receipt fields.** [`signature`](../../SPEC.md#42-required-fields),
  [`previous_receipt_hash`](../../SPEC.md#43-optional-fields),
  [`evidence_hash_sha512`](../../SPEC.md#42-required-fields),
  [`policy_hash`](../../SPEC.md#43-optional-fields),
  [`key_id`](../../SPEC.md#42-required-fields),
  [`timestamp`](../../SPEC.md#11-timestamp-anchoring-locked-decision-c-11)
  (RFC 3161, production profile).
- **Evidence type.** Supplemental control — technical implementation.
- **Verifier command.**
  `go run verifiers/go/verify.go example/receipt.json example/public_key.pem`
  → exit 0 on a valid signature, exit 1 on any modification. See
  [verifiers/go/verify.go](../../verifiers/go/verify.go).

### E015.2 — AI agent logging implementation
Source: [aiuc-1.com/accountability/log-model-activity](https://www.aiuc-1.com/accountability/log-model-activity)

- **Requirement.** Logs capture agent provenance metadata, tool call
  parameters and results, delegation records between sub-agents,
  authorization events, and (where available) reasoning traces.
- **AERF provides.** Each evidence receipt captures `agent`, `action`,
  `in_policy`, `policy_reason`, `policy_hash`, `compliance_tags`,
  `observed_at`, and (optionally) `output_hash`, `reasoning_hash`,
  `session_id`, and `session_trajectory` for in-session ordering. See
  the field table at [SPEC §4.2](../../SPEC.md#42-required-fields)
  and [§4.3](../../SPEC.md#43-optional-fields).
- **Coverage.** **Partial** — captures provenance, the action
  identifier, the authorization decision, optional output and
  reasoning digests, and recent session trajectory. Does *not* capture
  full multi-agent delegation chains nor inline reasoning text.
- **Gap.** Multi-agent delegation chain logging across distinct
  issuers is not specified in v0.1; tracked under held decision
  [C-12](../../DECISIONS.md#held-decisions) (dual signature) and
  flagged for v0.2 in
  [SPEC §13](../../SPEC.md#13-open-questions-for-v01-stable). Reasoning
  capture is model-dependent; AERF stores a `reasoning_hash`, not the
  reasoning bytes themselves (see SPEC §4.3).

### E015.1 — Logging implementation
Source: [aiuc-1.com/accountability/log-model-activity](https://www.aiuc-1.com/accountability/log-model-activity)

- **Requirement.** The system logs inputs, processing steps, outputs,
  and metadata sufficient to reconstruct each AI-driven action.
- **AERF provides.** AERF specifies the *format* of one such record.
  Inputs are bound through `evidence_hash_sha512` over the inline
  `evidence` object; outputs are bound through optional `output_hash`;
  metadata is bound through `agent`, `policy_hash`, `key_id`,
  `observed_at`, and `compliance_tags`. See SPEC
  [§4.2](../../SPEC.md#42-required-fields).
- **Coverage.** **Partial** — AERF is the receipt format; the
  surrounding logging *infrastructure* (collection pipelines, storage,
  retrieval, indexing, retention) is customer-implemented.
- **Gap.** AERF specifies the wire format, not the storage system.
  Customers must operate compatible producers (e.g.,
  [`agentmint`](https://github.com/aniketh-maddipati/agentmint-python))
  and durable storage with appropriate access controls.

### D003.3 — Tool call log
Source: [aiuc-1.com/reliability/restrict-unsafe-tool-calls](https://www.aiuc-1.com/reliability/restrict-unsafe-tool-calls)

- **Requirement.** Log entries capture the MCP server (or tool host),
  tool name, tool version, input parameters, and timestamps for each
  agent tool invocation.
- **AERF provides.** The `action` field carries the tool-call
  identifier (charset `[A-Za-z0-9_:.-]`, ≤128 chars per
  [SPEC §4.4](../../SPEC.md#44-field-constraints)). The `agent`,
  `observed_at`, and the inline `evidence` object carry tool name,
  arguments digest, and timing.
- **Coverage.** **Partial** — captures tool identity, agent identity,
  and timing with cryptographic integrity. Tool *version* and
  structured input parameters are carried opaquely inside `evidence`
  rather than as first-class fields.
- **Gap.** Structured tool-input fields (e.g., explicit `tool_name`,
  `tool_version`, `tool_arguments`) are not first-class in v0.1.
  Producers may use the inline `evidence` object to carry them today;
  a structured schema is a candidate for v0.2.

### B006.2 — Agent security monitoring
Source: [aiuc-1.com/security/enforce-contextual-access-controls](https://www.aiuc-1.com/security/enforce-contextual-access-controls)

- **Requirement.** Logging captures agent service calls and
  authentication/authorization attempts; boundary violations are
  detectable from the resulting log stream.
- **AERF provides.** Every receipt carries `in_policy` (boolean) and
  `policy_reason` (human-readable). A receipt with `in_policy: false`
  is a signed, immutable record of a boundary violation. The
  `policy_hash` field binds the decision to a specific ruleset, and
  `compliance_tags` carries the deployment's tag namespace (locked
  decision [C-14](../../DECISIONS.md#locked-decisions)).
- **Coverage.** **Partial** — provides the *evidence* of boundary
  decisions. Detection, alerting, and anomaly analysis are operational
  layers above AERF, not part of the receipt format.
- **Gap.** No alerting or correlation is specified by AERF. SIEM
  integration is straightforward (receipts are JSON) but is not part
  of the spec.

### B008.4 — Agentic interface data integrity
Source: [aiuc-1.com/security/protect-model-deployment-environment](https://www.aiuc-1.com/security/protect-model-deployment-environment)

- **Requirement.** Cryptographic message signing protects the
  integrity of agent-to-agent and agent-to-tool interface
  communications.
- **AERF provides.** Ed25519 signatures over canonical JSON. Every
  receipt is signed; receipts may optionally carry a second
  `agent_signature` from the acting agent's own key (held decision
  [C-12](../../DECISIONS.md#held-decisions)).
- **Coverage.** **Partial** — AERF signs *evidence receipts about*
  agent actions. AERF does not specify a signing scheme for the
  agent-to-agent transport itself; that remains a deployment concern.
- **Gap.** The transport-layer signing protocol between agents is out
  of scope (SPEC [§1.3](../../SPEC.md#13-out-of-scope)). AERF is a
  detached evidence layer, not a wire protocol for agent
  communication.

## Gaps — AIUC-1 controls AERF does not address

AERF makes *no* claim of coverage for the following. These remain the
customer's responsibility under the surrounding compliance program.

- **A. Data & Privacy (A001–A007).** AERF does not address PII
  filtering, consent management, data retention windows, output data
  rights, cross-customer data isolation, or trade-secret protection.
  AERF can carry a `patient_id_hash` (SPEC §4.5) but does not
  legislate that hashing.
- **B001–B005.** AERF does not perform adversarial robustness testing
  (B001), adversarial input detection (B002), public-disclosure
  management, endpoint scraping prevention, or real-time input
  filtering.
- **C. Safety (C001–C012).** AERF does not prevent harmful outputs,
  out-of-scope outputs, customer-defined high-risk outputs, or output
  vulnerabilities. AERF cannot flag content for human review; it can
  only sign the record that such a review occurred.
- **D001–D002.** AERF *logs* but does not *prevent* hallucinations.
- **E001–E003.** AERF provides forensic evidence after incidents; it
  does not define failure plans, escalation procedures, or incident
  response programs (those map to E-domain process controls separate
  from logging).
- **E016.** AERF does not implement user-facing AI-disclosure
  mechanisms.
- **F. Society.** AERF does not address cyber misuse prevention or
  CBRN risk.

## Auditor verification guide

A reviewer can confirm coverage of E015.4 in under five minutes
without installing AERF tooling beyond a Go compiler.

1. **Clone the repository.**
   ```bash
   git clone https://github.com/aerf-spec/aerf.git
   cd aerf/verifiers/go
   ```
2. **Run the reference verifier against the canonical example.**
   ```bash
   go run verify.go example/receipt.json example/public_key.pem
   ```
   Expected output:
   ```
   OK  receipt 7473e179
       type:      notarised_evidence
       agent:     claims-agent
       action:    submit:claim:CLM-9920
       in_policy: true
       key_id:    c348d3c785c92249
   ```
   Exit code: `0`.
3. **Confirm tamper detection.**
   ```bash
   go run verify.go example/receipt-tampered.json example/public_key.pem
   ```
   Expected: `FAIL signature verification FAILED ...`, exit code `1`.
   The tampered file differs from the original by a single
   character (`CLM-9920` → `CLM-9921`). The signature does not.
4. **Read the verifier source.**
   [`verifiers/go/verify.go`](../../verifiers/go/verify.go) is ~200
   lines, standard library only. Canonicalization is in the
   `canonicalize` function and matches the producer's
   `json.dumps(d, sort_keys=True, separators=(",",":"), ensure_ascii=True)`
   (see SPEC [§5.1](../../SPEC.md#51-canonical-json)).
5. **Inspect the canonical example receipt.**
   [`verifiers/go/example/receipt.json`](../../verifiers/go/example/receipt.json)
   shows the field set (signature, key_id, evidence_hash_sha512,
   policy_hash, plan_signature) used to satisfy E015.4 verbatim:
   *cryptographic hashing of log entries to ensure tamper-evidence and
   independent verifiability*.

What this verifies for an auditor: that any modification to a signed
AERF record — including a single-character change — is detected by a
verifier independent of the issuer, using only the issuer's public key
and a small, auditable tool.

## Proposal

We propose a targeted addition to AIUC-1 evidence guidance: reference
AERF as a named implementation option under E015.4 and E015.2,
alongside whatever examples currently appear (WORM storage,
third-party log management platforms, etc.). AERF is the
AI-agent-specific implementation of the same cryptographic-integrity
principle: a single-file wire format, a single-file standard-library
verifier, and zero vendor lock-in.

Concrete asks:
- E015.4 evidence example list: add "Ed25519-signed receipts with
  SHA-256 chain hashing per [AERF v0.1](https://github.com/aerf-spec/aerf)".
- E015.2 evidence example list: add the AERF receipt field set
  (`agent`, `action`, `in_policy`, `policy_hash`, `output_hash`,
  `reasoning_hash`) as one acceptable schema.
- D003.3 evidence example list: AERF receipts as an acceptable
  format for tool-call logs (with the v0.2 extension for structured
  tool-call fields).

Contact: open an issue at
[github.com/aerf-spec/aerf/issues](https://github.com/aerf-spec/aerf/issues),
or reach the editor via [agentmint.run](https://agentmint.run).

---

[← Back to Compliance Overview](../COMPLIANCE.md) · [← Back to README](../../README.md)
