# Changelog

All notable changes to AERF will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
AERF uses informal semantic versioning for its wire format (held decision C-18).

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
