# AERF × HIPAA

[← Compliance Overview](../COMPLIANCE.md) · [← README](../../README.md)

> **Scope.** AERF is an open wire format for cryptographic receipts of
> AI-agent actions. This page maps AERF v0.1.0-draft.1 to the HIPAA
> Security Rule's Audit Controls technical safeguard at 45 CFR
> §164.312(b). The page is written for a covered entity, business
> associate, or HIPAA assessor evaluating AERF as evidence for AI-agent
> actions involving electronic protected health information (ePHI).

AERF is in scope for the *audit-trail* requirement applied to AI-agent
actions on or with ePHI. AERF is out of scope for access control,
authentication, transmission security, or administrative and physical
safeguards.

| Item | Value |
|---|---|
| AERF version | v0.1.0-draft.1 (May 2026) |
| HIPAA source | 45 CFR Part 164 (eCFR current as of 2026-05) |
| Last verified | 2026-05-08 |

## Primary mapping

### 45 CFR §164.312(b) — Audit controls

Source: [eCFR — 45 CFR §164.312](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.312)

- **Regulatory text.** *"Implement hardware, software, and/or
  procedural mechanisms that record and examine activity in
  information systems that contain or use electronic protected
  health information."*
- **Implementation specification: Information system activity
  review (Required, 45 CFR §164.308(a)(1)(ii)(D)).** *"Implement
  procedures to regularly review records of information system
  activity, such as audit logs, access reports, and security
  incident tracking reports."*
- **AERF provides.** A signed, hash-chained receipt for every
  AI-agent action that touches ePHI, capturing
  [`agent`](../../SPEC.md#42-required-fields),
  [`action`](../../SPEC.md#42-required-fields),
  [`observed_at`](../../SPEC.md#42-required-fields),
  [`in_policy`](../../SPEC.md#42-required-fields),
  [`policy_hash`](../../SPEC.md#43-optional-fields), and an
  [`evidence_hash_sha512`](../../SPEC.md#42-required-fields)
  digest over the inline `evidence` payload (see
  [SPEC §4.2](../../SPEC.md#42-required-fields)). Receipts are
  independently verifiable using only the issuer's public key and
  a ~200-line standard-library Go verifier
  ([`verifiers/go/verify.go`](../../verifiers/go/verify.go)).
- **Coverage.** **Partial.** AERF provides full coverage of the
  technical audit-control mechanism portion. The procedural
  review under §164.308(a)(1)(ii)(D) (who reviews logs, on what
  cadence, what triggers escalation) remains a covered entity or
  business associate responsibility.
- **Gap.** Procedural review, escalation, and the broader
  administrative-safeguards program are organizational controls
  outside AERF's wire-format scope.

## Privacy considerations specific to PHI

The canonical AERF example hashes patient identifiers in the
inline `evidence` payload (`patient_id_hash` rather than
`patient_id`); see
[SPEC §4.5](../../SPEC.md#45-privacy-considerations) and held
decision [C-8](../../DECISIONS.md#held-decisions). Until C-8
resolves, deployments handling ePHI SHOULD hash sensitive
identifiers before inclusion in `evidence`, strip free-text PII
fields, and treat the inlined `evidence` as in-band-confidential.
A hash-only variant of the EVIDENCE profile is an open candidate
for v0.1.0 stable.

This is consistent with the HIPAA "minimum necessary" principle
(§164.502(b)) for inclusion of PHI in audit records: AERF
supports hash-only payloads so that the receipt remains
tamper-evident without the receipt itself becoming a fresh PHI
surface.

## Gaps — HIPAA controls AERF does not address

- **§164.312(a) — Access control.** Out of scope: AERF logs
  access decisions, it does not enforce them.
- **§164.312(c) — Integrity (of ePHI itself).** Out of scope:
  AERF protects the audit record's integrity, not the integrity
  of ePHI in the source system.
- **§164.312(d) — Person or entity authentication.** Out of
  scope: authentication is enforced before an action reaches
  the receipt layer.
- **§164.312(e) — Transmission security.** Out of scope: AERF
  receipts may be transmitted over any channel; AERF does not
  define a transport.
- **§164.308 — Administrative safeguards.** Workforce security,
  risk analysis, contingency planning, sanctions, and the
  procedural parts of audit control are organizational programs,
  not wire formats.
- **§164.310 — Physical safeguards.** Out of scope: AERF is a
  wire format, not a facility-access control.
- **§164.530 — Privacy Rule administrative requirements.** Out
  of scope: privacy-program requirements are organizational.
- **Breach notification (§164.400 series).** AERF receipts can
  serve as evidence during an incident investigation but do not
  implement notification workflows.

## Security model

The verifier trusts the issuer's public key (SPKI PEM, RFC 8410)
distributed out of band. The issuer's private key is held by the
covered entity or business associate; a key compromise breaks
the signature trust assumption regardless of chain integrity (see
[SPEC §12.3](../../SPEC.md#123-key-compromise)). AERF does not
encrypt receipts at rest; deployments handling ePHI must rely on
storage-layer encryption per §164.312(a)(2)(iv) for the archive.

## Auditor verification guide

The reference verifier checks the cryptographic integrity of any
AERF receipt without disclosing PHI in the payload. The exact
commands and expected output are documented in the
[AIUC-1 auditor verification guide](AIUC-1.md#auditor-verification-guide);
the same workflow applies here. The verifier source is at
[`verifiers/go/verify.go`](../../verifiers/go/verify.go), and the
canonical example receipt is at
[`verifiers/go/example/receipt.json`](../../verifiers/go/example/receipt.json).

Sources:

- [HHS — Summary of the HIPAA Security Rule](https://www.hhs.gov/hipaa/for-professionals/security/laws-regulations/index.html)
- [eCFR — 45 CFR §164.312 Technical safeguards](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.312)

---

[← Compliance Overview](../COMPLIANCE.md) · [← README](../../README.md)
