# AERF × SOC 2

[← Compliance Overview](../COMPLIANCE.md) · [← README](../../README.md)

> **Scope.** AERF is an open wire format for cryptographic receipts of
> AI-agent actions. This page maps AERF v0.1.0-draft.1 to the AICPA
> Trust Services Criteria CC7.2 (system monitoring) and CC7.3
> (security event evaluation). The page is written for a service
> organization, an SOC 2 examiner, or an implementer evaluating AERF
> as the evidence stream underpinning monitoring-and-incident
> controls.

AERF is in scope for the *evidence stream* underpinning monitoring
and incident-detection controls. AERF is out of scope for
organizational, administrative, and process controls (CC1–CC6, CC8,
CC9 and the availability / confidentiality / processing-integrity /
privacy categories beyond what overlaps with logging).

| Item | Value |
|---|---|
| AERF version | v0.1.0-draft.1 (May 2026) |
| Trust Services Criteria | 2017, with revised points of focus 2022 |
| Last verified | 2026-05-08 |

## Primary mappings

### CC7.2 — System monitoring

Source: [AICPA — 2017 Trust Services Criteria (with revised points of focus 2022)](https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria-with-revised-points-of-focus-2022)

- **Criterion (paraphrased from TSP section 100).** *"The entity
  monitors system components and the operation of those components
  for anomalies that are indicative of malicious acts, natural
  disasters, and errors affecting the entity's ability to meet its
  objectives; anomalies are analyzed to determine whether they
  represent security events."*
- **AERF provides.** A continuous, append-only stream of
  cryptographically signed receipts of AI-agent actions, each
  carrying [`agent`](../../SPEC.md#42-required-fields),
  [`action`](../../SPEC.md#42-required-fields),
  [`in_policy`](../../SPEC.md#42-required-fields),
  [`observed_at`](../../SPEC.md#42-required-fields),
  [`policy_hash`](../../SPEC.md#43-optional-fields), and optional
  `output_hash` and `reasoning_hash` (see
  [SPEC §4](../../SPEC.md#4-receipt-data-model)). Chain hashing
  per [SPEC §8](../../SPEC.md#8-hash-chaining-locked-decision-c-5)
  preserves ordering integrity across receipts in a plan.
- **Coverage.** **Partial.** AERF supplies a tamper-evident
  receipt stream that monitoring tooling consumes.
- **Gap.** Detection logic, alerting thresholds, and operational
  follow-up are above AERF.

### CC7.3 — Evaluation of security events

Source: [AICPA — 2017 Trust Services Criteria (with revised points of focus 2022)](https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria-with-revised-points-of-focus-2022)

- **Criterion (paraphrased).** *"The entity evaluates security
  events to determine whether they could or have resulted in a
  failure of the entity to meet its objectives (security
  incidents) and, if so, takes actions to prevent or address such
  failures."*
- **AERF provides.** Each receipt with `in_policy: false` is a
  signed record of a boundary-violating attempt by the agent.
  `policy_reason` carries the human-readable rationale. The chain
  ([SPEC §8](../../SPEC.md#8-hash-chaining-locked-decision-c-5))
  lets an investigator reconstruct the sequence of receipts
  leading up to and following the event without trusting any
  single intermediary.
- **Coverage.** **Partial.** AERF preserves the evidence.
- **Gap.** The evaluation procedure (severity scoring,
  escalation, remediation) remains organizational.

## Auxiliary mappings

- **CC7.1 — Detection of vulnerabilities.** Out of scope: AERF
  does not perform vulnerability scanning.
- **CC4.1 — Monitoring of controls.** AERF receipts can serve as
  evidence that automated controls (policy gates) operated as
  designed during the audit period, since each gate decision
  produces a signed receipt. Coverage: **Partial** (evidence
  supply only).

## Why AERF specifically applies to SOC 2 examinations

SOC 2 Type II examinations evaluate controls over a period
(typically 6–12 months). The traditional pattern is a
point-in-time export of log files, with the auditor relying on
the service organization's attestation that the logs were not
modified. AERF receipts are independently verifiable for the
entire examination period: the auditor can verify any sample
receipt directly from the issuer's public key without trusting
the service organization's log-handling chain.

## Gaps — SOC 2 criteria AERF does not address

- **CC1 — Control environment.** Out of scope: governance,
  ethics, and oversight are organizational programs.
- **CC2 — Communication and information.** Out of scope beyond
  the receipt format itself.
- **CC3 — Risk assessment.** Out of scope: risk identification
  and analysis are organizational activities.
- **CC5 — Control activities.** Out of scope: AERF does not
  implement controls; it records that they fired.
- **CC6 — Logical and physical access.** Out of scope: AERF logs
  access decisions but does not enforce them.
- **CC8 — Change management.** Out of scope: AERF binds receipts
  to a `policy_hash` but does not implement the
  change-approval process.
- **CC9 — Risk mitigation.** Out of scope: mitigation programs
  are organizational.
- **A-, C-, P-, PI- categories.** Out of scope: availability
  monitoring, encryption of confidential data at rest, privacy
  notice and consent, and processing-integrity reconciliations
  are not within the AERF wire format.

## Security model

The verifier trusts the issuer's public key, distributed out of
band per
[SPEC §9.2](../../SPEC.md#92-public-key-transport-held-decision-c-10).
The issuer's private key is held by the service organization; a
key compromise breaks the signature trust assumption (see
[SPEC §12.3](../../SPEC.md#123-key-compromise)). AERF does not
prevent a malicious issuer from signing false statements; that
is mitigated at the deployment layer via independent observation
or external publication of chain roots.

## Auditor verification guide

The verifier workflow is identical across frameworks; see the
[AIUC-1 auditor verification guide](AIUC-1.md#auditor-verification-guide)
for exact commands and expected output. The verifier source is at
[`verifiers/go/verify.go`](../../verifiers/go/verify.go); the
canonical example receipt is at
[`verifiers/go/example/receipt.json`](../../verifiers/go/example/receipt.json).
The independent-verifier property is the relevant SOC 2 property:
an external auditor can verify any sample receipt without
involving the service organization's tooling.

Sources:

- [AICPA — 2017 Trust Services Criteria (with revised points of focus 2022)](https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria-with-revised-points-of-focus-2022)

---

[← Compliance Overview](../COMPLIANCE.md) · [← README](../../README.md)
