# AERF Design Decisions

> **Status:** v0.1.0-draft.1 — Public Review Draft. Locked decisions are
> binding for v0.1.0 stable; held decisions remain open for community
> input until v0.1.0 stable.

This document is the single source of truth for the design decisions
underlying [SPEC.md](./SPEC.md). Each decision is identified by a stable
`C-N` tag so issues, PRs, and external references can cite it directly.

## Locked decisions

These are binding for v0.1.0 and will not change before v1.0 except via
a deprecation cycle.

| ID | Topic | Decision |
|----|-------|----------|
| **C-1** | Signing algorithm | Multi-algorithm with registry. Receipts declare their algorithm. v0.1 registry: **Ed25519 only**. |
| **C-2** | Chain hash algorithm | Multi-hash with registry. `previous_receipt_hash` declares its hash algorithm. v0.1 registry: **SHA-256**. |
| **C-3** | Internal field hashes | Caller-specified per field. Each digest declares its algorithm (e.g. by field-name suffix `_sha512`, or via accompanying algorithm field). |
| **C-5** | Chain topology | **Merkle tree required from v0.1.** A linear chain is treated as the degenerate single-leaf-per-level case. The reference verifier in v0.1.0-draft.1 verifies signatures only; chain verification is described normatively in the spec but is **optional in the reference verifier** for this draft. |
| **C-6** | Genesis sentinel | The `previous_receipt_hash` field is **omitted entirely** on the first receipt of a chain. Verifiers MUST treat absence of the field as the genesis signal. Presence of the field with `null`, empty string, or any zero-value is a conformance error. |
| **C-7** | Chain hash input | **Payload only.** The signature bytes are excluded from the hash input. This allows chain verification without access to signature material and decouples key rotation from chain integrity. |
| **C-11** | Timestamp authority | RFC 3161 trusted timestamps are **REQUIRED** for the production profile. The base profile MAY use self-reported `observed_at` timestamps. |
| **C-13** | Enforcement-mode field | **NOT in the spec.** The `mode` / `original_verdict` fields used by some libraries are a library-only convention. Mentioned in the non-normative annex (SPEC.md Appendix A) only. |
| **C-14** | Compliance tags | A generic `compliance_tags` array is the normative field. The hardcoded `aiuc_controls` field is **deprecated** and will be removed by v1.0. |
| **C-16** | Replay protection | Per-profile. AERF-AUTHZ tokens are single-use; AERF-EVIDENCE has no replay concept. v0.1 ships EVIDENCE only. |
| **C-19** | Conformance levels | A single level — "conformant" or "non-conformant". No Issuer / Verifier / Auditor distinctions. |
| **C-20** | Compliance mappings | Community PR with editor approval. |

## Held decisions

These are **acknowledged in the spec but not yet locked.** Current
behavior describes the v0.1.0-draft.1 reference producer (`agentmint`
0.1.x); the field is open to revision before v0.1.0 stable.

| ID | Topic | Current behavior | Open question |
|----|-------|------------------|---------------|
| **C-4** | Canonicalization | Compact JCS subset: `json.dumps(d, sort_keys=True, separators=(",", ":"), ensure_ascii=True)` | Adopt full RFC 8785 JCS for stable v0.1, or document the subset as the normative form? |
| **C-8** | Evidence inlining | Inline by default. | Should the spec require / recommend / prohibit hash-only references for sensitive fields? |
| **C-9** | Key ID format | First 16 hex chars of SHA-256(public key). | Move to a JWK thumbprint (RFC 7638) or keep the 16-hex-char convention? |
| **C-10** | Public-key transport | SPKI PEM (RFC 8410, 12-byte prefix + 32-byte raw key). | Add JWK / DID alternatives, or keep PEM as the only normative form? |
| **C-12** | Dual signature | Optional second signature by the agent's own key. | Make agent co-signature normative for multi-agent scenarios? |
| **C-15** | Receipt ID format | UUIDv4. | UUIDv7 for time-ordered IDs, content-addressed IDs, or keep UUIDv4? |
| **C-17** | Profile structure | v0.1 ships EVIDENCE only. | When to specify AERF-AUTHZ; what other profiles are needed? |
| **C-18** | Versioning policy | Semver-for-wire-format informally. | Adopt a formal versioning scheme distinct from implementation semver? |

## Process

- Locked decisions change only via a deprecation cycle (one minor
  version of warning before removal).
- Held decisions resolve before v0.1.0 stable. Resolutions move from
  this table into the spec body.
- New decisions are assigned the next available `C-N` tag (see issues
  for C-21 onward).
- Compliance framework mappings (C-20) are community contributions;
  open a PR under `compliance/` once that directory lands in
  v0.1.0-draft.2.
