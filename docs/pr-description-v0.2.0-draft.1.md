# v0.2.0-draft.1: close C-12 (compromised-child false-truth-claim)

Reported by John Truong. Threat-model rationale in THREAT-MODEL.md
§6.3.1 and SPEC.md §12.5.

## What lands

- SPEC.md §4.6 multi-agent verification fields: `parent_signature`,
  `pdp_signature`, `context_hash_sha256`, `log_inclusion_proof`,
  `impact_tags`.
- SPEC.md §15 transparency log conformance criteria (5 MUST / 2 SHOULD).
- SPEC.md §16 counter-signature semantics (sync / async hybrid + MMD).
- SPEC.md §17 impact-tag registry (6 normative core tags +
  `x-{vendor}-` namespace).
- SPEC.md §5.1 full RFC 8785 (JCS) plus NFC and string-encoded
  numbers in hashed context. Resolves held C-4.
- SPEC.md §12.5-12.7 (compromised lower agent, common-mode failure,
  tag stripping).
- Locks C-4, C-12. Adds C-21..C-24.
- schemas/aerf-v0.2.json with conditional rules.
- 12 conformance vectors under vectors/.
- tools/aerf-adversary/ pen-testing library, 11 attacks.
- Go reference verifier: parent / PDP / log proof verification.
- THREAT-MODEL.md and RESOLUTION-PLAN.md.
- CI workflow.

## Known limits documented in v0.2 (forward path in RESOLUTION-PLAN.md)

- **Tag stripping (SPEC.md §12.7).** A compromised child can omit
  `impact_tags` to bypass the sync counter-sign requirement. Defense
  at v0.2 is upstream PEP tag pinning (operational). Mechanical
  closure ships in v0.3.0-draft.2 via PEP-side tag signing
  (RESOLUTION-PLAN.md §6.1).
- **Common-mode failure (SPEC.md §12.6).** Same poisoned upstream
  context reaching all signers produces honestly-signed wrong claims.
  Out of scope for the receipt layer; composition with upstream
  provenance (in-toto / SLSA / C2PA) is the answer
  (RESOLUTION-PLAN.md §8.1).
- **Quorum compromise (A11).** Adversary holds 2+ keys from
  {agent, issuer, parent, PDP, log, witness}. Forensic-only via the
  transparency log. Cryptographically irreducible
  (RESOLUTION-PLAN.md §10).

## Deviations from the prompt to flag

Three additions the prompt did not ask for, kept because the editor
finds them load-bearing for adoption. None affect the conformance
surface.

- **Go verifier delta exceeds the prompt's 500-LOC budget.** Actual
  is ~880 LOC across `internal/aerf/` and `cmd/aerf-verify/` plus
  `cmd/aerf-render/`. The `cmd/`/`internal/` layout split is Go-
  idiomatic and not the source of the overrun; the addition of
  multi-agent verification, log inclusion proof verification, and
  the renderer accounts for it. Flagging for the record.
- **`verifiers/go/cmd/aerf-render/`.** A convenience tool that
  produces a self-contained HTML report from a verified receipt.
  Safety posture documented in `verifiers/go/README.md`. Not part
  of the v0.2 conformance surface.
- **`tools/build-vectors.py` and `tools/aerf_primitives.py`.** A
  reproducible vector generator and a shared primitives module.
  Generator-produced vectors are byte-stable across re-runs, which
  makes the regression check tractable. Treated as developer
  tooling; not part of the conformance surface.

## Closing

Closes #5 (C-12 dual signature held decision). Forward-references
RESOLUTION-PLAN.md §6.1 for the tag-stripping closure that ships
in v0.3.0-draft.2.
