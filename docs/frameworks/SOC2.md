# AERF × SOC 2

[← Back to Compliance Overview](../COMPLIANCE.md) · [← Back to README](../../README.md)

This page maps AERF receipts to the AICPA Trust Services Criteria
(2017, with revised points of focus 2022). AERF is in scope for the
*evidence stream* underpinning monitoring and incident-detection
controls. It is out of scope for organizational, administrative, and
process controls (CC1–CC6, CC8, CC9 and the availability /
confidentiality / processing-integrity / privacy categories beyond
what overlaps with logging).

Source: [AICPA — 2017 Trust Services Criteria (with revised points of focus 2022)](https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria-with-revised-points-of-focus-2022).

## Primary mappings

### CC7.2 — System monitoring

- **Criterion (paraphrased from TSP section 100).** "The entity
  monitors system components and the operation of those components
  for anomalies that are indicative of malicious acts, natural
  disasters, and errors affecting the entity's ability to meet its
  objectives; anomalies are analyzed to determine whether they
  represent security events."
- **AERF provides.** A continuous, append-only stream of
  cryptographically signed records of AI-agent actions, each carrying
  `agent`, `action`, `in_policy`, `observed_at`, `policy_hash`, and
  optional `output_hash` and `reasoning_hash` (see
  [SPEC §4](../../SPEC.md#4-receipt-data-model)). Chain hashing
  ([SPEC §8](../../SPEC.md#8-hash-chaining-locked-decision-c-5))
  guarantees ordering integrity across receipts in a plan.
- **Coverage.** **Partial.** AERF supplies tamper-evident telemetry
  that monitoring tooling consumes. The detection logic, alerting
  thresholds, and operational follow-up are above AERF.

### CC7.3 — Evaluation of security events

- **Criterion (paraphrased).** "The entity evaluates security events
  to determine whether they could or have resulted in a failure of
  the entity to meet its objectives (security incidents) and, if so,
  takes actions to prevent or address such failures."
- **AERF provides.** Each receipt with `in_policy: false` is a signed
  record of a boundary-violating attempt by the agent. `policy_reason`
  carries the human-readable rationale. The chain (SPEC §8) lets an
  investigator reconstruct the sequence of receipts leading up to and
  following the event without trusting any single intermediary.
- **Coverage.** **Partial.** AERF preserves the evidence; the
  evaluation procedure (severity scoring, escalation, remediation)
  remains organizational.

## Auxiliary mappings

- **CC7.1 — Detection of vulnerabilities.** AERF does not perform
  vulnerability scanning. Out of scope.
- **CC4.1 — Monitoring of controls.** AERF receipts can serve as
  evidence that automated controls (policy gates) operated as designed
  during the audit period, since each gate decision produces a signed
  receipt.

## Why AERF specifically helps SOC 2 examinations

SOC 2 Type II examinations evaluate controls over a period (typically
6–12 months). The traditional pattern is a point-in-time export of
log files, with the auditor relying on the service organization's
attestation that the logs were not modified. AERF receipts are
independently verifiable for the entire examination period: the
auditor can verify any sample receipt directly from the issuer's
public key without trusting the service organization's log-handling
chain.

## Gaps — SOC 2 criteria AERF does not address

- **CC1 — Control environment.** Governance, ethics, oversight. Out
  of scope.
- **CC2 — Communication and information.** Out of scope beyond the
  receipt format itself.
- **CC3 — Risk assessment.** Out of scope.
- **CC5 — Control activities.** AERF does not implement the controls;
  it records that they fired.
- **CC6 — Logical and physical access.** AERF logs access decisions
  but does not enforce them.
- **CC8 — Change management.** Out of scope.
- **CC9 — Risk mitigation.** Out of scope.
- **A-, C-, P-, PI- categories.** Availability monitoring, encryption
  of confidential data at rest, privacy notice and consent, processing
  integrity reconciliations — all out of scope.

## Auditor verification guide

The verifier workflow is identical across frameworks; see
[AIUC-1.md#auditor-verification-guide](AIUC-1.md#auditor-verification-guide).
The independent-verifier property is the value-add for SOC 2: an
external auditor can verify any sample receipt without involving the
service organization's tooling.

Sources:
- [AICPA — 2017 Trust Services Criteria (with revised points of focus 2022)](https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria-with-revised-points-of-focus-2022)

---

[← Back to Compliance Overview](../COMPLIANCE.md) · [← Back to README](../../README.md)
