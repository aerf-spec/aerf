# AERF × AIUC-1

[← Compliance Overview](../COMPLIANCE.md) · [← README](../../README.md)

> **Scope.** AERF is an open wire format for cryptographic receipts of
> AI-agent actions. This page maps AERF v0.1.0-draft.1 to AIUC-1
> control identifiers cited in the Q1–Q2 2026 published evidence list.
> The page is written for a standards-body reviewer, an AIUC-1
> assessor, or an implementer evaluating AERF as candidate evidence for
> AIUC-1 logging controls.

AIUC-1 is the AI Usage Controls standard, organized into six domains
(A. Data & Privacy, B. Security, C. Safety, D. Reliability,
E. Accountability, F. Society). The full evidence list is published at
[aiuc-1.com/evidence](https://www.aiuc-1.com/evidence). AERF is in
scope for the **evidence and logging layer**. AERF is out of scope
for adversarial testing, output safety, input filtering, and
policy/programmatic controls.

| Item | Value |
|---|---|
| AERF version | v0.1.0-draft.1 (May 2026) |
| AIUC-1 source | aiuc-1.com published controls, sourced 2026-05 |
| Last verified | 2026-05-08 |

## Contents

- [Primary mappings](#primary-mappings)
- [Gaps — AIUC-1 controls AERF does not address](#gaps--aiuc-1-controls-aerf-does-not-address)
- [Security model](#security-model)
- [AERF-conformant for E015.4 — implementer checklist](#aerf-conformant-for-e0154--implementer-checklist)
- [Auditor verification guide](#auditor-verification-guide)
- [Proposal](#proposal)

## Primary mappings

### E015.4 — Log integrity protection

Source: [aiuc-1.com/accountability/log-model-activity](https://www.aiuc-1.com/accountability/log-model-activity)

- **Requirement (paraphrased from the AIUC-1 evidence page).** Logs
  of AI system activity are tamper-evident and independently
  verifiable through cryptographic hashing or equivalent integrity
  protections.
- **AERF provides.** Every receipt is signed with Ed25519
  (RFC 8032) over the canonical JSON payload (see
  [SPEC §5.1](../../SPEC.md#51-canonical-json) and
  [§7](../../SPEC.md#7-signing-procedure)). Receipts within a plan
  chain via SHA-256 of the previous canonical payload (see
  [SPEC §8](../../SPEC.md#8-hash-chaining-locked-decision-c-5)).
- **Coverage.** **Full** for the cryptographic-integrity portion of
  the control. AERF does not provision storage, retention, or access
  control for log archives.
- **Receipt fields.**
  [`signature`](../../SPEC.md#42-required-fields),
  [`previous_receipt_hash`](../../SPEC.md#43-optional-fields),
  [`evidence_hash_sha512`](../../SPEC.md#42-required-fields),
  [`policy_hash`](../../SPEC.md#43-optional-fields),
  [`key_id`](../../SPEC.md#42-required-fields),
  [`timestamp`](../../SPEC.md#11-timestamp-anchoring-locked-decision-c-11)
  (RFC 3161, production profile).
- **Gap.** Storage durability, retention duration, and access control
  for the receipt archive remain customer responsibilities. AERF
  defines the wire format only.

### E015.2 — AI agent logging implementation

Source: [aiuc-1.com/accountability/log-model-activity](https://www.aiuc-1.com/accountability/log-model-activity)

- **Requirement (paraphrased).** Logs capture agent provenance
  metadata, tool call parameters and results, delegation records
  between sub-agents, authorization events, and (where available)
  reasoning traces.
- **AERF provides.** Each evidence receipt captures `agent`,
  `action`, `in_policy`, `policy_reason`, `policy_hash`,
  `compliance_tags`, `observed_at`, and (optionally) `output_hash`,
  `reasoning_hash`, `session_id`, and `session_trajectory` for
  in-session ordering. See
  [SPEC §4.2](../../SPEC.md#42-required-fields) and
  [§4.3](../../SPEC.md#43-optional-fields).
- **Coverage.** **Partial.** AERF captures provenance, action
  identifier, the authorization decision, optional output and
  reasoning digests, and recent session trajectory.
- **Gap.** Multi-agent delegation chain logging across distinct
  issuers is not specified in v0.1; tracked under held decision
  [C-12](../../DECISIONS.md#held-decisions) (dual signature) and
  flagged for v0.2 in
  [SPEC §13](../../SPEC.md#13-open-questions-for-v01-stable).
  Reasoning capture is model-dependent; AERF stores a
  `reasoning_hash`, not the reasoning bytes themselves.

### E015.1 — Logging implementation

Source: [aiuc-1.com/accountability/log-model-activity](https://www.aiuc-1.com/accountability/log-model-activity)

- **Requirement (paraphrased).** The system logs inputs, processing
  steps, outputs, and metadata sufficient to reconstruct each
  AI-driven action.
- **AERF provides.** AERF specifies the format of one such record.
  Inputs are bound through `evidence_hash_sha512` over the inline
  `evidence` object; outputs are bound through optional
  `output_hash`; metadata is bound through `agent`, `policy_hash`,
  `key_id`, `observed_at`, and `compliance_tags`. See
  [SPEC §4.2](../../SPEC.md#42-required-fields).
- **Coverage.** **Partial.** AERF is the receipt format. The
  surrounding logging infrastructure (collection pipelines, storage,
  retrieval, indexing, retention) is customer-implemented.
- **Gap.** AERF specifies the wire format, not the storage system.
  Customers operate compatible producers (e.g.,
  [`agentmint`](https://github.com/aniketh-maddipati/agentmint-python))
  and durable storage with appropriate access controls.

### D003.3 — Tool call log

Source: [aiuc-1.com/reliability/restrict-unsafe-tool-calls](https://www.aiuc-1.com/reliability/restrict-unsafe-tool-calls)

- **Requirement (paraphrased).** Log entries capture the MCP server
  (or tool host), tool name, tool version, input parameters, and
  timestamps for each agent tool invocation.
- **AERF provides.** The `action` field carries the tool-call
  identifier (charset `[A-Za-z0-9_:.-]`, ≤128 chars per
  [SPEC §4.4](../../SPEC.md#44-field-constraints)). The `agent`,
  `observed_at`, and inline `evidence` object carry tool name,
  arguments digest, and timing.
- **Coverage.** **Partial.** AERF captures tool identity, agent
  identity, and timing with cryptographic integrity.
- **Gap.** Structured tool-input fields (e.g., explicit `tool_name`,
  `tool_version`, `tool_arguments`) are not first-class in v0.1.
  Producers may carry them inside the inline `evidence` object;
  a structured schema is a candidate for v0.2.

### B006.2 — Agent security monitoring

Source: [aiuc-1.com/security/enforce-contextual-access-controls](https://www.aiuc-1.com/security/enforce-contextual-access-controls)

- **Requirement (paraphrased).** Logging captures agent service
  calls and authentication/authorization attempts; boundary
  violations are detectable from the resulting log stream.
- **AERF provides.** Every receipt carries `in_policy` (boolean)
  and `policy_reason` (human-readable). A receipt with
  `in_policy: false` is a signed, immutable record of a boundary
  violation. The `policy_hash` field binds the decision to a
  specific ruleset, and `compliance_tags` carries the deployment's
  tag namespace per locked decision
  [C-14](../../DECISIONS.md#locked-decisions).
- **Coverage.** **Partial.** AERF provides the evidence of boundary
  decisions.
- **Gap.** No alerting or correlation is specified by AERF. SIEM
  integration is straightforward (receipts are JSON) but is not
  part of the spec.

### B008.4 — Agentic interface data integrity

Source: [aiuc-1.com/security/protect-model-deployment-environment](https://www.aiuc-1.com/security/protect-model-deployment-environment)
*(URL inferred from AIUC-1 path conventions; pending verification
against the published evidence list at
[aiuc-1.com/evidence](https://www.aiuc-1.com/evidence).)*

- **Requirement (paraphrased).** Cryptographic message signing
  protects the integrity of agent-to-agent and agent-to-tool
  interface communications.
- **AERF provides.** Ed25519 signatures over canonical JSON. Every
  receipt is signed; receipts may optionally carry a second
  `agent_signature` from the acting agent's own key (held decision
  [C-12](../../DECISIONS.md#held-decisions)).
- **Coverage.** **Partial.** AERF signs evidence receipts about
  agent actions.
- **Gap.** The transport-layer signing protocol between agents is
  out of scope (see [SPEC §1.3](../../SPEC.md#13-out-of-scope)).
  AERF is a detached evidence layer, not a wire protocol for
  agent communication.

## Gaps — AIUC-1 controls AERF does not address

AERF makes no claim of coverage for the following. These remain the
customer's responsibility under the surrounding compliance program.

- **A. Data & Privacy (A001–A007).** AERF does not address PII
  filtering, consent management, data retention windows, output
  data rights, cross-customer data isolation, or trade-secret
  protection. AERF can carry a `patient_id_hash` (see
  [SPEC §4.5](../../SPEC.md#45-privacy-considerations)) but does
  not legislate that hashing.
- **B001–B005.** AERF does not perform adversarial robustness
  testing (B001), adversarial input detection (B002),
  public-disclosure management, endpoint scraping prevention, or
  real-time input filtering. Out of scope: these are runtime
  defenses, not evidence formats.
- **C. Safety (C001–C012).** AERF does not prevent harmful outputs,
  out-of-scope outputs, customer-defined high-risk outputs, or
  output vulnerabilities. AERF cannot flag content for human
  review; it can only sign the record that such a review occurred.
- **D001–D002.** AERF logs but does not prevent hallucinations.
  Detection is a model-evaluation concern outside the receipt
  layer.
- **E001–E003.** AERF provides forensic evidence after incidents.
  Failure plans, escalation procedures, and incident response
  programs are E-domain process controls separate from logging.
- **E016.** AERF does not implement user-facing AI-disclosure
  mechanisms; disclosure is a UX control, not an evidence-format
  control.
- **F. Society.** AERF does not address cyber misuse prevention or
  CBRN risk. These are policy and capability controls outside
  AERF's scope.

## Security model

The AERF security model relies on three assumptions (see
[SPEC §12](../../SPEC.md#12-security-considerations)). First, the
issuer's private key is honestly held at the moment of signing —
key compromise breaks the signature trust assumption regardless of
chain integrity. Second, the verifier obtains the correct public
key out of band; AERF does not specify key distribution. Third,
RFC 3161 trusted timestamps are required for the production
profile to bind receipts to wall-clock time independently of the
issuer (locked decision
[C-11](../../DECISIONS.md#locked-decisions)). AERF does not
protect against malicious issuers signing false statements; that
is mitigated at the deployment layer via independent observation
and external publication of chain roots.

## AERF-conformant for E015.4 — implementer checklist

To use AERF as evidence for AIUC-1 E015.4, an implementer must:

1. Run a producer that emits AERF-EVIDENCE receipts per
   [SPEC §4](../../SPEC.md#4-receipt-data-model). The reference
   producer is
   [`agentmint-python`](https://github.com/aniketh-maddipati/agentmint-python).
2. Sign each receipt with Ed25519 over the canonical JSON payload
   per [SPEC §5.1](../../SPEC.md#51-canonical-json) and
   [§7](../../SPEC.md#7-signing-procedure).
3. Maintain a per-plan SHA-256 chain on
   `previous_receipt_hash` per
   [SPEC §8](../../SPEC.md#8-hash-chaining-locked-decision-c-5),
   omitting the field on the genesis receipt (locked decision
   [C-6](../../DECISIONS.md#locked-decisions)).
4. For the production profile, anchor the signed payload with an
   RFC 3161 trusted timestamp per
   [SPEC §11](../../SPEC.md#11-timestamp-anchoring-locked-decision-c-11).
5. Publish the issuer's public key in SPKI PEM (RFC 8410) form per
   [SPEC §9.2](../../SPEC.md#92-public-key-transport-held-decision-c-10).
6. Retain receipts in storage of the implementer's choice, with
   retention duration meeting the surrounding compliance program's
   requirements (AERF does not legislate retention).

An auditor confirms conformance by running the reference verifier
against a sample of receipts and the published public key.

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

   ```text
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

   Expected output:

   ```text
   FAIL signature verification FAILED for receipt 7473e179
   ```

   Exit code: `1`. The tampered file differs from the original by a
   single character (`CLM-9920` → `CLM-9921`); the signature does
   not.

4. **Read the verifier source.**
   [`verifiers/go/verify.go`](../../verifiers/go/verify.go) is ~200
   lines, standard library only. Canonicalization is in the
   `canonicalize` function and matches the producer's
   `json.dumps(d, sort_keys=True, separators=(",",":"), ensure_ascii=True)`
   (see [SPEC §5.1](../../SPEC.md#51-canonical-json)).

5. **Inspect the canonical example receipt.**
   [`verifiers/go/example/receipt.json`](../../verifiers/go/example/receipt.json)
   shows the field set (`signature`, `key_id`,
   `evidence_hash_sha512`, `policy_hash`, `plan_signature`) used to
   satisfy E015.4's tamper-evidence and independent-verifiability
   requirement.

What this verifies for an auditor: that any modification to a
signed AERF record — including a single-character change — is
detected by a verifier independent of the issuer, using only the
issuer's public key and a small, auditable tool.

## Proposal

We propose a targeted addition to AIUC-1 evidence guidance:
reference AERF as a named implementation option under E015.4 and
E015.2, alongside whatever examples currently appear (WORM
storage, third-party log management platforms). AERF is the
AI-agent-specific implementation of the same
cryptographic-integrity principle: a single-file wire format and
a single-file standard-library verifier.

Concrete asks:

- **E015.4 evidence example list:** add "Ed25519-signed receipts
  with SHA-256 chain hashing per
  [AERF v0.1](https://github.com/aerf-spec/aerf)".
- **E015.2 evidence example list:** add the AERF receipt field
  set (`agent`, `action`, `in_policy`, `policy_hash`,
  `output_hash`, `reasoning_hash`) as one acceptable schema.
- **D003.3 evidence example list:** add AERF receipts as an
  acceptable format for tool-call logs (with a v0.2 extension for
  structured tool-call fields).

Contact: open an issue at
[github.com/aerf-spec/aerf/issues](https://github.com/aerf-spec/aerf/issues),
or reach the editor via [agentmint.run](https://agentmint.run).

---

[← Compliance Overview](../COMPLIANCE.md) · [← README](../../README.md)
