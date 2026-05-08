# AERF × HIPAA

[← Back to Compliance Overview](../COMPLIANCE.md) · [← Back to README](../../README.md)

This page maps AERF receipts to the HIPAA Security Rule's Audit
Controls technical safeguard. AERF is in scope for the *audit-trail*
requirement applied to AI-agent actions on or with electronic
protected health information (ePHI). It is out of scope for access
control, authentication, transmission security, or administrative and
physical safeguards.

Source: HHS Security Rule overview at
[hhs.gov/hipaa/for-professionals/security/laws-regulations](https://www.hhs.gov/hipaa/for-professionals/security/laws-regulations/index.html);
regulatory text at
[eCFR 45 CFR §164.312](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.312).

## Primary mapping

### 45 CFR §164.312(b) — Audit controls

- **Regulatory text.** "Implement hardware, software, and/or
  procedural mechanisms that record and examine activity in
  information systems that contain or use electronic protected health
  information."
- **Implementation specification: Information system activity review
  (Required, 45 CFR §164.308(a)(1)(ii)(D)).** "Implement procedures to
  regularly review records of information system activity, such as
  audit logs, access reports, and security incident tracking
  reports."
- **AERF provides.** A signed, hash-chained receipt for every AI-agent
  action that touches ePHI, capturing `agent`, `action`,
  `observed_at`, `in_policy`, `policy_hash`, and an
  `evidence_hash_sha512` over the inline `evidence` payload (see
  [SPEC §4.2](../../SPEC.md#42-required-fields)). Receipts are
  independently verifiable using only the issuer's public key and a
  ~200-line standard-library Go verifier.
- **Coverage.** **Partial — full coverage of the technical
  audit-control mechanism portion**; the procedural review under
  §164.308(a)(1)(ii)(D) (who reviews logs, on what cadence, what
  triggers escalation) remains a covered entity / business associate
  responsibility.

## Privacy considerations specific to PHI

The canonical AERF example hashes patient identifiers in the inline
`evidence` payload (`patient_id_hash` rather than `patient_id`). See
[SPEC §4.5](../../SPEC.md#45-privacy-considerations) and held decision
[C-8](../../DECISIONS.md#held-decisions). Until C-8 resolves,
deployments handling ePHI **should** hash sensitive identifiers before
inclusion in `evidence`, strip free-text PII fields, and treat the
inlined `evidence` as in-band-confidential. A hash-only variant of the
EVIDENCE profile is an open candidate for v0.1.0 stable.

This is consistent with the HIPAA "minimum necessary" principle
(§164.502(b)) for inclusion of PHI in audit records: AERF supports
hash-only payloads so that the receipt remains tamper-evident without
the receipt itself becoming a fresh PHI surface.

## Gaps — HIPAA controls AERF does not address

- **§164.312(a) — Access control.** Out of scope. AERF logs the
  decision; it does not enforce access.
- **§164.312(c) — Integrity (of ePHI itself).** AERF protects the
  *audit record's* integrity, not the integrity of the ePHI in the
  source system.
- **§164.312(d) — Person or entity authentication.** Out of scope.
- **§164.312(e) — Transmission security.** Out of scope.
- **§164.308 — Administrative safeguards.** Workforce security, risk
  analysis, contingency planning, sanctions, and the *procedural*
  parts of audit control (who reviews logs, how, on what cadence) are
  out of scope.
- **§164.310 — Physical safeguards.** Out of scope.
- **§164.530 — Privacy Rule administrative requirements.** Out of
  scope.
- **Breach notification (§164.400 series).** AERF receipts can serve
  as evidence during an incident investigation but do not implement
  notification workflows.

## Auditor verification guide

The reference verifier checks the cryptographic integrity of any AERF
receipt without disclosing PHI in the payload. See the AIUC-1
auditor guide for the exact commands; the same workflow applies here:
[AIUC-1.md#auditor-verification-guide](AIUC-1.md#auditor-verification-guide).
The verifier source is at
[verifiers/go/verify.go](../../verifiers/go/verify.go).

Sources:
- [HHS — Summary of the HIPAA Security Rule](https://www.hhs.gov/hipaa/for-professionals/security/laws-regulations/index.html)
- [eCFR — 45 CFR §164.312 Technical safeguards](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.312)

---

[← Back to Compliance Overview](../COMPLIANCE.md) · [← Back to README](../../README.md)
