# AERF Design Decisions

> **Status:** v0.2.0-draft.1 — Public Review Draft. Locked decisions are
> binding for v0.2.0 stable; held decisions remain open until v0.3 unless
> otherwise noted.

This document is the single source of truth for the design decisions
underlying [SPEC.md](./SPEC.md). Each decision is identified by a stable
`C-N` tag so issues, PRs, and external references can cite it directly.

## Locked decisions

These are binding and will not change before v1.0 except via a
deprecation cycle.

| ID | Topic | Decision |
|----|-------|----------|
| **C-1** | Signing algorithm | Multi-algorithm with registry. Receipts declare their algorithm. v0.2 registry: **Ed25519 only** for issuer, parent, PDP, and log STH signatures. |
| **C-2** | Chain hash algorithm | Multi-hash with registry. `previous_receipt_hash` declares its hash algorithm. v0.2 registry: **SHA-256**. |
| **C-3** | Internal field hashes | Caller-specified per field. Each digest declares its algorithm (e.g. by field-name suffix `_sha512`, or via accompanying algorithm field). |
| **C-4** | Canonicalization | **Full RFC 8785 (JCS)**, with two normative tightenings: (1) all strings are Unicode-normalized to NFC before JCS encoding; (2) numeric values inside any object whose canonical bytes are fed into `context_hash_sha256` are encoded as JSON strings rather than JSON numbers. Resolves the v0.1 held form. v0.1 receipts produced under the §5.1 subset remain valid under v0.2 verifiers because the subset is contained in JCS for the field set v0.1 actually used. |
| **C-5** | Chain topology | **Merkle tree required from v0.1.** A linear chain is treated as the degenerate single-leaf-per-level case. |
| **C-6** | Genesis sentinel | The `previous_receipt_hash` field is **omitted entirely** on the first receipt of a chain. Verifiers MUST treat absence of the field as the genesis signal. Presence of the field with `null`, empty string, or any zero-value is a conformance error. |
| **C-7** | Chain hash input | **Payload only.** The signature bytes are excluded from the hash input. Extended in v0.2 by C-24. |
| **C-11** | Timestamp authority | RFC 3161 trusted timestamps are **REQUIRED** for the production profile. The base profile MAY use self-reported `observed_at` timestamps. |
| **C-12** | Dual signature / compromised lower agent | **Closed in v0.2.** Multi-agent verification fields land in SPEC.md §4.6: `parent_signature` (counter-signature; sync MUST when `impact_tags` is non-empty, async MUST within MMD for delegated actions); `pdp_signature` over the canonical JSON of `{context_hash_sha256, policy_hash, in_policy}`; `log_inclusion_proof` against a conformant transparency log (§15); and `impact_tags` from the closed core registry (§17). Threat-model rationale in §12.5 and [THREAT-MODEL.md](./THREAT-MODEL.md). |
| **C-13** | Enforcement-mode field | **NOT in the spec.** Library-only convention; mentioned in the non-normative annex (SPEC.md Appendix A) only. |
| **C-14** | Compliance tags | A generic `compliance_tags` array is the normative field. The hardcoded `aiuc_controls` field is **deprecated** and will be removed by v1.0. The new `impact_tags` field is distinct from `compliance_tags`; see C-21. |
| **C-16** | Replay protection | Per-profile. AERF-AUTHZ tokens are single-use; AERF-EVIDENCE has no replay concept. v0.2 ships EVIDENCE only. |
| **C-19** | Conformance levels | A single level — "conformant" or "non-conformant". No Issuer / Verifier / Auditor distinctions. |
| **C-20** | Compliance mappings | Community PR with editor approval. |
| **C-21** | Impact-tag registry governance | v0.2 ships a **closed core registry** (six tags: `HIPAA-PHI-WRITE`, `HIPAA-PHI-DELETE`, `FINANCE-TRADE-EXEC`, `FINANCE-DISBURSEMENT`, `AGENT-AGENT-DELEGATION`, `AGENT-EXTERNAL-CALL`) plus a vendor namespace `x-{vendor}-` for deployment-local extensions. Additions to the core registry require a spec revision. A working-group escalation process is future work. |
| **C-22** | Transparency log conformance | A conformant log MUST: be append-only with a signed STH at fixed cadence; support witness cosignature; declare an MMD; provide RFC 6962 §2.1.2 Merkle consistency proofs; expose a public read API. A conformant log SHOULD: gossip STHs out-of-band; publish a key rotation policy. See SPEC.md §15. |
| **C-23** | Counter-signature sync vs async | Hybrid. `parent_signature` MUST be present at verification time when `impact_tags` is non-empty (sync). `parent_signature` MUST be present within MMD when the action delegates to a child agent and `impact_tags` is empty (async). Otherwise OPTIONAL. See SPEC.md §16. |
| **C-24** | Chain-hash strip rule expansion | Extends C-7. The fields stripped before computing the `previous_receipt_hash` input now include: `signature`, `timestamp`, `parent_signature`, `parent_key_id`, `log_inclusion_proof`. Pre-issuance, claim-bearing fields (`pdp_signature`, `pdp_key_id`, `context_hash_sha256`, `impact_tags`) remain inside the chain-hash input. |

## Held decisions

These are **acknowledged in the spec but not yet locked.** Target
version for held items is v0.3.

| ID | Topic | Current behavior | Open question |
|----|-------|------------------|---------------|
| **C-8** | Evidence inlining | Inline by default. | Should the spec require / recommend / prohibit hash-only references for sensitive fields? |
| **C-9** | Key ID format | First 16 hex chars of SHA-256(public key), applied uniformly to `key_id`, `parent_key_id`, `pdp_key_id`. | Move to a JWK thumbprint (RFC 7638) or keep the 16-hex-char convention? |
| **C-10** | Public-key transport | SPKI PEM (RFC 8410). | Add JWK / DID alternatives, or keep PEM as the only normative form? |
| **C-15** | Receipt ID format | UUIDv4. | UUIDv7, content-addressed, or keep UUIDv4? |
| **C-17** | Profile structure | v0.2 ships EVIDENCE only. | When to specify AERF-AUTHZ; what other profiles are needed? |
| **C-18** | Versioning policy | Informal wire-format semver. | Adopt a formal versioning scheme distinct from implementation semver? |

## Process

- Locked decisions change only via a deprecation cycle (one minor
  version of warning before removal).
- Held decisions resolve before v0.3 unless re-deferred.
- New decisions are assigned the next available `C-N` tag.
- Compliance framework mappings (C-20) are community contributions
  under `docs/frameworks/`.
