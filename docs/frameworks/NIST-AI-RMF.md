# AERF × NIST AI RMF

[← Compliance Overview](../COMPLIANCE.md) · [← README](../../README.md)

> **Scope.** AERF is an open wire format for cryptographic receipts of
> AI-agent actions. This page maps AERF v0.1.0-draft.1 to NIST AI RMF
> 1.0 subcategories GOVERN 1.4, MAP 2.2, and MEASURE 2.8. The page is
> written for an organization adopting AI RMF, an AI risk reviewer,
> or an implementer evaluating AERF for the documentation-and-
> traceability subcategories.

The AI RMF is voluntary guidance. AERF is in scope for the
*documentation and traceability* subcategories. AERF is out of scope
for the broader governance, mapping, and measurement processes.

| Item | Value |
|---|---|
| AERF version | v0.1.0-draft.1 (May 2026) |
| AI RMF version | 1.0 (NIST AI 100-1, January 2023) |
| Last verified | 2026-05-08 |

## Primary mappings

### GOVERN 1.4 — Risk management process documented

Source: [NIST AI 100-1 — AI Risk Management Framework 1.0](https://nvlpubs.nist.gov/nistpubs/ai/nist.ai.100-1.pdf);
[AIRC — AI RMF Core](https://airc.nist.gov/airmf-resources/airmf/5-sec-core/).

- **Subcategory text (paraphrased).** *"The risk management
  process and its outcomes are established through transparent
  policies, procedures, and other controls based on
  organizational risk priorities."*
- **AERF provides.** Receipts carry
  [`policy_hash`](../../SPEC.md#43-optional-fields) (a SHA-256 of
  the canonicalized plan policy) and
  [`compliance_tags`](../../SPEC.md#43-optional-fields) per
  locked decision
  [C-14](../../DECISIONS.md#locked-decisions). Each receipt is a
  transparent, machine-verifiable record that a documented
  policy was applied to a specific action — establishing
  outcomes through transparent controls.
- **Coverage.** **Partial.** AERF provides the per-action
  evidence layer.
- **Gap.** The policy authoring, communication, and review
  process is organizational.

### MAP 2.2 — AI system knowledge limits documented

Source: [NIST AI 100-1 — AI Risk Management Framework 1.0](https://nvlpubs.nist.gov/nistpubs/ai/nist.ai.100-1.pdf).

- **Subcategory text (paraphrased).** *"Information about the AI
  system's knowledge limits and how system output may be utilized
  and overseen by humans is documented."*
- **AERF provides.** Receipts can carry an optional
  [`reasoning_hash`](../../SPEC.md#43-optional-fields) binding
  the agent's reasoning text, an
  [`output_hash`](../../SPEC.md#43-optional-fields) binding the
  action output, and
  [`session_trajectory`](../../SPEC.md#43-optional-fields)
  capturing recent in-session actions (see
  [SPEC §4.3](../../SPEC.md#43-optional-fields)). Where a human
  review or oversight step occurs, the deployment can record it
  inside `evidence` and the receipt's signature binds that
  record.
- **Coverage.** **Partial.** AERF supports recording the
  oversight steps.
- **Gap.** Defining and communicating the system's knowledge
  limits is upstream of the receipt.

### MEASURE 2.8 — Risks and benefits documented

Source: [NIST AI 100-1 — AI Risk Management Framework 1.0](https://nvlpubs.nist.gov/nistpubs/ai/nist.ai.100-1.pdf).

- **Subcategory text (paraphrased).** *"Risks associated with
  transparency and accountability ... are examined and
  documented."*
- **AERF provides.** Receipts are themselves the accountability
  artifact: tamper-evident, independently verifiable, and tied
  to a `policy_hash`. The presence or absence of receipts (and
  their `in_policy` outcomes) is examined documentation.
- **Coverage.** **Partial.** AERF is the documentation.
- **Gap.** The examination procedure is organizational.

## Auxiliary mappings

- **GOVERN 1.5 — Ongoing monitoring and review.** Receipts feed
  the ongoing monitoring stream. Coverage: **Partial**.
- **MAP 4.1 — Approaches and methods to track third-party
  capabilities and risks.** AERF receipts are exchangeable
  across organizational boundaries because verification is
  independent of the issuer's infrastructure. Coverage:
  **Partial**.
- **MANAGE 4.1 — Post-deployment AI system monitoring.** AERF
  captures the per-action evidence side of the loop. Coverage:
  **Partial**.

## Gaps — AI RMF subcategories AERF does not address

- **GOVERN 2–6.** Out of scope: organizational structure,
  accountability assignment, diverse perspectives, and AI
  risk-management training are organizational programs.
- **MAP 1, 3, 4, 5.** Out of scope: context, capabilities,
  benefits-and-costs, and third-party impact assessment are
  upstream activities.
- **MEASURE 1, 3, 4.** Out of scope: appropriate methods, error
  rates, and feedback mechanisms are model-evaluation and
  product-design concerns; AERF logs but does not measure
  performance.
- **MANAGE 1–3.** Out of scope: risk prioritization, response
  planning, and third-party risks are organizational.

## Why AERF specifically applies to AI RMF adopters

The AI RMF emphasizes *trustworthy* AI characteristics, including
"Accountable and Transparent" (Section 3.5). AERF instantiates a
specific, open, vendor-neutral mechanism for accountability: a
verifier-independent record format that any third party can audit
without first negotiating access to the issuer's tooling.

## Security model

The verifier trusts the issuer's public key, distributed out of
band per
[SPEC §9.2](../../SPEC.md#92-public-key-transport-held-decision-c-10).
The issuer's private key is held by the organization deploying
the AI system; a key compromise breaks the signature trust
assumption (see [SPEC §12.3](../../SPEC.md#123-key-compromise)).
The "Accountable and Transparent" property the AI RMF describes
is realized only when issuer keys and chain roots are
discoverable to the verifier.

## Auditor verification guide

The verifier workflow is identical across frameworks; see the
[AIUC-1 auditor verification guide](AIUC-1.md#auditor-verification-guide)
for exact commands and expected output. The verifier source is at
[`verifiers/go/verify.go`](../../verifiers/go/verify.go); the
canonical example receipt is at
[`verifiers/go/example/receipt.json`](../../verifiers/go/example/receipt.json).

Sources:

- [NIST AI 100-1 — AI Risk Management Framework 1.0](https://nvlpubs.nist.gov/nistpubs/ai/nist.ai.100-1.pdf)
- [NIST AI RMF Playbook](https://www.nist.gov/itl/ai-risk-management-framework/nist-ai-rmf-playbook)
- [AIRC — AI RMF Core](https://airc.nist.gov/airmf-resources/airmf/5-sec-core/)

---

[← Compliance Overview](../COMPLIANCE.md) · [← README](../../README.md)
