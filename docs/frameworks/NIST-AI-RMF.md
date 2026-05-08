# AERF × NIST AI RMF

[← Back to Compliance Overview](../COMPLIANCE.md) · [← Back to README](../../README.md)

This page maps AERF receipts to the NIST AI Risk Management Framework
(AI RMF 1.0, NIST AI 100-1, January 2023). The AI RMF is voluntary
guidance; AERF is in scope for the *documentation and traceability*
subcategories and out of scope for the broader governance, mapping,
and measurement processes.

Source: [NIST AI 100-1 — Artificial Intelligence Risk Management Framework (AI RMF 1.0)](https://nvlpubs.nist.gov/nistpubs/ai/nist.ai.100-1.pdf).

## Primary mappings

### GOVERN 1.4 — Risk management process documented

- **Subcategory text (paraphrased).** "The risk management process
  and its outcomes are established through transparent policies,
  procedures, and other controls based on organizational risk
  priorities."
- **AERF provides.** AERF receipts carry `policy_hash` (a SHA-256 of
  the canonicalized plan policy) and `compliance_tags` per locked
  decision [C-14](../../DECISIONS.md#locked-decisions). Each receipt
  is therefore a transparent, machine-verifiable record that a
  documented policy was applied to a specific action — establishing
  outcomes through transparent controls.
- **Coverage.** **Partial.** AERF provides the per-action evidence
  layer; the policy authoring, communication, and review process is
  organizational.

### MAP 2.2 — AI system knowledge limits documented

- **Subcategory text (paraphrased).** "Information about the AI
  system's knowledge limits and how system output may be utilized and
  overseen by humans is documented."
- **AERF provides.** Receipts can carry an optional `reasoning_hash`
  binding the agent's reasoning text, an `output_hash` binding the
  action output, and `session_trajectory` capturing recent in-session
  actions (see [SPEC §4.3](../../SPEC.md#43-optional-fields)). Where a
  human review or oversight step occurs, the deployment can record it
  inside `evidence` and the receipt's signature binds that record.
- **Coverage.** **Partial.** AERF supports recording the oversight
  steps; defining and communicating the system's knowledge limits is
  upstream of the receipt.

### MEASURE 2.8 — Risks and benefits documented

- **Subcategory text (paraphrased).** "Risks associated with
  transparency and accountability ... are examined and documented."
- **AERF provides.** Receipts are themselves the accountability
  artifact: tamper-evident, independently verifiable, and tied to a
  policy hash. The presence or absence of receipts (and their
  `in_policy` outcomes) is examined documentation.
- **Coverage.** **Partial.** AERF is the documentation; the
  examination is procedural.

## Auxiliary mappings

- **GOVERN 1.5 — Ongoing monitoring and review.** Receipts feed the
  ongoing monitoring stream.
- **MAP 4.1 — Approaches and methods to track third-party
  capabilities and risks.** AERF receipts are exchangeable across
  organizational boundaries because verification is independent of
  the issuer's infrastructure.
- **MANAGE 4.1 — Post-deployment AI system monitoring** plans
  include mechanisms for "capturing and evaluating input from users
  and other relevant AI actors". AERF captures the per-action
  evidence side of this loop.

## Gaps — AI RMF subcategories AERF does not address

- **GOVERN 2–6** — most are organizational structure, accountability
  assignment, diverse perspectives, AI risk-management training.
  Out of scope.
- **MAP 1, 3, 4, 5** — context, capabilities, benefits-and-costs,
  third-party impact assessment. Out of scope.
- **MEASURE 1, 3, 4** — appropriate methods, error rates,
  feedback mechanisms. Out of scope; AERF logs but does not measure
  performance.
- **MANAGE 1–3** — risk prioritization, response planning, third-
  party risks. Out of scope.

## Why AERF specifically helps AI RMF adopters

The AI RMF emphasizes *trustworthy* AI characteristics including
"Accountable and Transparent" (Section 3.5). AERF instantiates a
specific, open, vendor-neutral mechanism for accountability: a
verifier-independent record format that any third party can audit
without first negotiating access to the issuer's tooling.

## Auditor / reviewer guide

See [AIUC-1.md#auditor-verification-guide](AIUC-1.md#auditor-verification-guide)
for the verifier workflow. The verifier source is at
[verifiers/go/verify.go](../../verifiers/go/verify.go).

Sources:
- [NIST AI 100-1 — AI Risk Management Framework 1.0](https://nvlpubs.nist.gov/nistpubs/ai/nist.ai.100-1.pdf)
- [NIST AI RMF Playbook](https://www.nist.gov/itl/ai-risk-management-framework/nist-ai-rmf-playbook)
- [AIRC — AI RMF Core](https://airc.nist.gov/airmf-resources/airmf/5-sec-core/)

---

[← Back to Compliance Overview](../COMPLIANCE.md) · [← Back to README](../../README.md)
