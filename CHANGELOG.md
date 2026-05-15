# Changelog

All notable changes to AERF will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
AERF uses informal semantic versioning for its wire format (held decision C-18).

## [v0.2.0-draft.1] — 2026-05-11

**Public review draft. Not yet stable. Closes C-12 (compromised-child
false-truth-claim attack).** Reported by John Truong.

### Added

- SPEC.md §4.6 multi-agent verification fields: `parent_signature`,
  `parent_key_id`, `parent_evaluation_path_id`, `pdp_signature`,
  `pdp_key_id`, `context_hash_sha256`, `log_inclusion_proof`,
  `impact_tags`.
- SPEC.md §6.3 algorithm registry for context hashing (SHA-256 only
  in v0.2).
- SPEC.md §15 transparency log integration with five MUST and two
  SHOULD conformance criteria for conformant logs.
- SPEC.md §16 counter-signature semantics (sync vs async hybrid,
  Maximum Merge Delay bound, independence of evaluation).
- SPEC.md §17 impact-tag registry: six normative core tags plus the
  `x-{vendor}-` namespace for deployment-local extensions.
- `schemas/aerf-v0.2.json` with conditional requirements wired to
  `impact_tags`, `parent_signature`, and `pdp_signature`.
- `THREAT-MODEL.md` — companion threat-model document for v0.2.
- `vectors/` directory with 12 conformance vectors covering happy
  path, rejections, and known limits.
- `tools/aerf-adversary/` pen-testing library (10 attacks; runs
  against any verifier via subprocess).
- `tools/run-vectors.py` and `tools/check-schemas.py` dispatchers.
- `Makefile` targets: `verify-vectors`, `schema-check`, `adversary`,
  `test`, `all`.
- `.github/workflows/verify.yml` CI workflow.

### Changed

- SPEC.md §5.1 now mandates full RFC 8785 (JCS) plus NFC
  normalization and string-encoded numbers inside any object hashed
  into `context_hash_sha256`. Resolves held C-4.
- SPEC.md §8.4 chain-hash strip rules extended to exclude
  `parent_signature`, `parent_key_id`, and `log_inclusion_proof`
  (see C-24). Pre-issuance fields (`pdp_signature`, `pdp_key_id`,
  `context_hash_sha256`, `impact_tags`) remain inside the chain-hash
  input.
- SPEC.md §12 security considerations: new subsections 12.5
  (compromised lower agent), 12.6 (common-mode failure), 12.7 (tag
  stripping).
- Go reference verifier (`verifiers/go/`): adds `canonicalize.go`
  (RFC 8785 JCS) and `multi_agent.go` (parent / PDP / log proof
  verification). Adds CLI flags `--parent-key`, `--pdp-key`,
  `--log-key`, `--require-parent-sig`, `--require-pdp-sig`,
  `--require-log`. Backwards compatible: v0.1-shaped receipts
  continue to verify with no flags.

### Resolved

- **C-4** Canonicalization — full RFC 8785 with NFC + string-encoded
  numbers in context.
- **C-12** Dual signature / compromised lower agent — see SPEC.md
  §4.6, §12.5, §16, §17.

### Added (decisions)

- **C-21** Impact-tag registry governance (closed core, vendor
  namespace).
- **C-22** Transparency log conformance criteria.
- **C-23** Counter-signature sync vs async hybrid.
- **C-24** Chain-hash strip rule expansion.

### Known limits (out of scope for v0.2)

- Common-mode failure on poisoned upstream context (SPEC.md §12.6,
  THREAT-MODEL.md §10.1).
- Receipt-layer tag stripping (SPEC.md §12.7); defense is upstream
  Policy Enforcement Point.

## [v0.1.0-draft.1] — 2026-05-06

**Public review draft. Not yet stable. Wire format may change before v0.1.0.**

Initial public review draft of the Agent Evidence Receipt Format.

### Added

- `SPEC.md` — AERF-EVIDENCE profile specification (draft).
- `DECISIONS.md` — locked design decisions C-1 through C-20 and held items.
- Go reference verifier (`verifiers/go/`) — Ed25519 signature verification,
  standard library only, ~200 lines, single static binary when built.
- Canonical example artifact set under `verifiers/go/example/`:
  signed receipt, tampered receipt (action mutated), public key (SPKI PEM),
  full evidence ZIP from the `agentmint` reference producer.
- `schemas/aerf-v0.1.json` — JSON Schema (Draft 2020-12) for the
  EVIDENCE receipt shape.
- Dual-license setup: prose under CC BY 4.0 (`LICENSE-spec`); code,
  schemas, and example artifacts under Apache 2.0 (`LICENSE`).

### Deferred to v0.1.0-draft.2 or later

- Test vectors directory (8 vectors).
- Python and TypeScript reference verifiers.
- Compliance framework mappings (`compliance/`).
- Governance, contributing, and security documents.
- CI workflows and pre-built verifier binaries.
- AERF-AUTHZ profile (held decision C-17).
- Library-side fixes for chain-hash input (C-7) and genesis sentinel (C-6);
  the v0.1.0-draft.1 example is a single genesis receipt to sidestep
  the current library/spec gap.
