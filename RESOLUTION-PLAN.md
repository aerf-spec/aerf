# AERF — Threat Resolution Plan

> **Status:** Engineering plan companion to `THREAT-MODEL.md`. Maps every
> threat from the model to a concrete resolution: already closed,
> closeable in patches, closeable in v0.3, closeable in v1.0+,
> closeable only by composition with other formats, or
> cryptographically irreducible. Not normative; the spec is the source
> of truth for what conformant implementations do.
>
> **Editor:** Aniketh Maddipati. Reviewers welcome.

---

## 1. Scope and status

This document exists because the threat model lists residuals and
out-of-scope items without committing to engineering paths for them.
That's appropriate for a threat model (its job is to characterize
risk) and inappropriate for the project's planning (which needs to
know what gets built when). This document closes that gap.

Every threat in `THREAT-MODEL.md` §6 is accounted for here. For each,
one of six dispositions applies:

1. **Closed in v0.2.** No further work. Referenced only for completeness.
2. **v0.2 patch.** Tighten spec language before v0.1.0-draft.2 ships.
3. **v0.3 work item.** Material design and code, defined here.
4. **v1.0+ direction.** Long-horizon, sketched not specified.
5. **Composition.** Out of scope for AERF; addressable by pairing with
   another format. The pattern is documented here.
6. **Cryptographically irreducible.** Acknowledged; no engineering path
   exists at the receipt layer.

The aim is to leave nothing in a "we'll see" state. Items that genuinely
need a design call before they can move are flagged as **open
questions** inside the relevant section.

---

## 2. Method

For each v0.3 work item, the same shape applies:

- **Threat(s) closed.** Cross-reference to `THREAT-MODEL.md`.
- **Mechanism.** What changes, concretely.
- **Schema additions.** New fields, types, encodings.
- **Spec sections affected.** Where in `SPEC.md` the normative text lands.
- **Verifier work.** What the Go reference verifier needs to do.
- **Test vectors required.** What we add to `vectors/` and the pen-test library.
- **Backwards compatibility.** What happens to v0.2 receipts.
- **Open design questions.** Decisions that need locking before implementation.

Items that are not v0.3 work get lighter treatment proportional to
their horizon.

---

## 3. Disposition map

One table, all threats. Use this as the index; each row points to the
section where the resolution lives.

| Threat | Capability | v0.2 status | Resolution | Section |
|---|---|---|---|---|
| Plain forgery (6.1.1) | A1 | Closed | none needed | §4 |
| Field tampering (6.1.2) | A1 | Closed | none needed | §4 |
| Schema confusion (6.1.3) | A1, A4 | Closed | none needed | §4 |
| Malformed receipt (6.1.4) | A1 | Closed | none needed | §4 |
| Signature malleability (6.1.5) | A1 | Closed by primitive | none needed | §4 |
| Hash length-extension (6.1.6) | A1 | n/a | none needed | §4 |
| Chain reorder (6.2.1) | A1 | Closed | none needed | §4 |
| Skip a link (6.2.2) | A1 | Mitigated w/ log | strengthened by v0.3-4 | §6.4 |
| Genesis spoof (6.2.3) | A1, A4 | Mitigated w/ caveats | strengthened by v0.3-4 | §6.4 |
| Fork (6.2.4) | A4 | Mitigated by log | strengthened by v0.3-4 | §6.4 |
| Re-sign with rotated key (6.2.5) | A4 | Mitigated in production | v0.2 patch: normative timestamp | §5 |
| C-12 base case (6.3.1) | A3 | Closed | strengthened by v0.3-1, v0.3-3 | §6.1, §6.3 |
| **Tag stripping (6.3.2)** | A3 | **Documented limit** | **v0.3-1: PEP-side tag signing** | **§6.1** |
| Split-context (6.3.3) | A3, A6 | Closed | none needed | §4 |
| Replay in EVIDENCE (6.3.4) | A1 | Documented limit | **v0.3-2: AUTHZ profile** | §6.2 |
| PDP bypass (6.3.5) | A3, A4 | Closed | none needed | §4 |
| Common-mode failure (6.3.6) | A10 | Documented limit | **v0.3-3: path attestation; §8.1 composition** | §6.3, §8.1 |
| Log omission (6.4.1) | A7 | Closed (fail-closed) | none needed | §4 |
| Log split-view (6.4.2) | A7 | Closed with witness | **v0.3-5: witness quorum spec** | §6.5 |
| Backdated entries (6.4.3) | A7 | Mitigated beyond MMD | strengthened by v0.3-5 | §6.5 |
| Retention violation (6.4.4) | A7 | Closed | none needed | §4 |
| Log key compromise (6.4.5) | A7 | Mitigated w/ quorum | strengthened by v0.3-5 | §6.5 |
| Canonicalization (6.5.x) | A1 | Closed | none needed | §4 |
| Long-term issuer key compromise (6.6.1) | A4 | Mitigated (timestamps) | v0.2 patch: normative timestamp | §5 |
| Cross-role key reuse (6.6.2) | OP | Mitigated (SHOULD warn) | **v0.3-7: tighten to MUST reject** | §6.7 |
| Weak RNG / shared seed (6.6.3) | impl flaw | Out of scope | operational guidance | §9 |
| Impact-tag namespace pollution (6.7.1) | A9 | Closed (registry closed) | none needed | §4 |
| Conformant-log registry capture (6.7.2) | A9 | Future work | **v0.3-4: conformant log registry** | §6.4 |
| Witness collusion (6.7.3) | A8 quorum | Mitigated w/ quorum | **v0.3-5: witness quorum spec** | §6.5 |
| Prompt injection at ingestion (6.8.1) | A10 | Out of scope | **§8.1 composition** | §8.1 |
| Tool poisoning (6.8.2) | A10 | Out of scope | **§8.1 composition** | §8.1 |
| Memory contamination (6.8.3) | A10 | Out of scope | **§8.1 composition** | §8.1 |
| Retrieval poisoning (6.8.4) | A10 | Out of scope | **§8.1 composition** | §8.1 |
| Common-mode across signers (6.8.5) | A10 | Documented limit | v0.3-3 + §8.1 composition | §6.3, §8.1 |
| Parent DoS (6.9.1) | A1, A10 | Mitigated (fail-closed) | operational guidance | §9 |
| MMD-window evasion (6.9.2) | A1, A10 | Mitigated w/ OP-3 | operational guidance | §9 |
| TOCTOU (6.9.3) | A3 | Closed | none needed | §4 |
| Clock skew (6.9.4) | A1 | Mitigated in production | v0.2 patch: normative timestamp | §5 |
| Quorum compromise (A11) | A11 | Degraded to forensic | irreducible | §10 |
| Verifier key acquisition (OP-1) | OP | Out of scope | **§8.2 composition: JWK Set / DID** | §8.2 |
| Hardware key isolation | OP | Out of scope | **§7.2 + §8.3 composition** | §7.2, §8.3 |
| Privacy / selective disclosure | n/a | Out of scope | **§7.1: BBS+/ZK direction** | §7.1 |

Three rows are bolded because they are the most consequential
unresolved items. The rest are either closed, mechanical patches, or
defensible residuals.

---

## 4. Already closed in v0.2 (reference only)

No engineering work required. Listed for completeness and so reviewers
can see what defenses are doing the load-bearing for which threats.

| Defense | Threats closed | Mechanism |
|---|---|---|
| Ed25519 signature (§7) | 6.1.1, 6.1.2, 6.1.5 | RFC 8032 EUF-CMA |
| Canonical JSON (§5.1) | 6.5.1–6.5.6 | RFC 8785 + NFC + string-encoded numbers |
| Chain hash (§8) | 6.2.1, 6.2.2, 6.2.3 | SHA-256 over canonical payload, with strip rules |
| Schema validation (§4) | 6.1.3, 6.1.4 | JSON Schema Draft 2020-12 |
| parent_signature (§4.6, §16) | 6.3.1 | Independent counter-sign for high-impact actions |
| pdp_signature with tuple binding (§4.6, §17) | 6.3.3, 6.3.5, 6.9.3 | Verdict bound to (context_hash, policy_hash, in_policy) |
| Log inclusion proof (§4.6, §15) | 6.4.1, 6.4.4 | RFC 9162 audit path against witness-cosigned STH |
| Witness cosignature (§15) | 6.4.2, 6.4.3 | Independent attestation to STH; consistency proofs catch backdating |
| Closed impact-tag registry (§17) | 6.7.1 | Core 6 tags; vendor namespace; no runtime additions to core |

---

## 5. v0.2 patches before draft.2

Small normative tightenings worth landing before the next draft. None
require schema changes; all are spec-text or verifier-CLI-default
changes.

### 5.1 Normative timestamp requirement for production profile

**Threat:** 6.2.5 (re-sign with rotated key), 6.6.1 (long-term issuer
key compromise), 6.9.4 (clock skew).

**Mechanism:** §11 currently SHOULD-recommends RFC 3161 trusted
timestamps. Promote to MUST for the production profile. Receipts
without a valid timestamp from an RFC 3161 TSA are accepted at the
base profile but rejected at the production profile.

**Spec change:** §3 conformance, §11 normative text. No schema change
(timestamp field already exists at §4.4).

**Verifier change:** `--require-timestamp` flag defaults to true in
production mode.

**Cost:** Low. Spec text and verifier flag default.

### 5.2 Witness count minimum bumped from informational to SHOULD

**Threat:** 6.4.5, 6.7.3.

**Mechanism:** §15 currently states multi-witness is recommended for
production without specifying a count. Tighten to "SHOULD be ≥2
administratively independent witnesses; receipts with fewer are
accepted but treated as base profile."

This is a halfway step before the full v0.3-5 work. The full quorum
specification lives in §6.5; this patch just plants the SHOULD ≥2
flag.

**Cost:** Low. Spec text only.

### 5.3 Cross-role key collision warning becomes structured diagnostic

**Threat:** 6.6.2.

**Mechanism:** §10.1 currently says verifier SHOULD warn on
`key_id` collisions across roles. Patch: emit a machine-parseable
diagnostic line on stderr in a fixed format so monitors can grep.

This is preparation for v0.3-7, which upgrades the warning to a hard
reject.

**Cost:** Low. Verifier output format only.

---

## 6. v0.3 work items

This section is the substance of the document. Each item is a
self-contained proposal: threat, mechanism, schema, spec sections,
verifier work, test vectors, backwards compatibility, open questions.

The numbering (v0.3-1 through v0.3-8) is for reference, not priority.
Priority order is in §11.

### 6.1 v0.3-1: PEP-side tag signing

**Threats closed:** 6.3.2 (tag stripping). Strengthens 6.3.1 (C-12 base)
by making the impact-tag set itself unforgeable by the agent.

**Mechanism.** Every receipt MUST carry a `pep_signature` over a
canonicalized tag-set object. The PEP signs whether or not impact
tags are present; absence of tags is itself a signed claim. The
verifier rejects any receipt where `pep_signature` is missing, where
`pep_signed_tag_set.tags` does not equal `receipt.impact_tags` as a
set, or where the signature does not verify against the PEP's public
key.

This is the structurally cleanest closure: the question "did the PEP
endorse the tag set the verifier is seeing" becomes mechanical.

Two options were considered and rejected:

| Option | Why rejected |
|---|---|
| Profile flag: strict deployments require pep_signature, lax don't | Deployments that should be strict but aren't pay no protection. The closure has to be universal. |
| Make tag absence implicit (pep_signature only when tags present) | Tag stripping becomes the trivial bypass: attacker omits both the tag and the signature. The PEP MUST sign in both cases for the defense to mean anything. |

**Schema additions:**

```json
{
  "pep_signature": "hex 128 chars (Ed25519)",
  "pep_key_id": "hex 16 chars",
  "pep_signed_tag_set": {
    "tags": ["HIPAA-PHI-WRITE", "..."],
    "signed_at": "2026-05-11T17:42:03Z"
  }
}
```

Encoding: hex throughout (matches §4 convention). `pep_signed_tag_set`
is its own canonical JSON object; the PEP signs over its RFC 8785
canonicalization with NFC and string-encoded numbers (per locked
C-4 in v0.2).

**Spec sections affected:**

- §3 conformance: new step "verify pep_signature and tag-set equality."
- §4.6: add the three fields.
- §7: clarify that the PEP signature is generated independently of
  the issuer signature (different key, different operational
  domain).
- §8.4 chain-hash strip rules: `pep_signature` is **included in
  payload** (it's a claim, not added after issuance, same logic as
  pdp_signature in v0.2).
- §17 impact-tag registry: cross-reference the new field.
- §12.7 (current "documented limit" subsection for tag stripping):
  rewrite to describe v0.3 closure.

**Verifier work:** ~80 LOC.

- Function `verifyPEPSignature(receipt, pepPublicKey)`.
- Set-equality check between `pep_signed_tag_set.tags` and
  `impact_tags`.
- Reject on mismatch, missing signature, or signature failure.
- CLI: `--pep-key <path>` (analogous to existing `--parent-key`,
  `--pdp-key`, `--log-key`).
- Backwards compat: if `--pep-key` is not supplied and no
  `pep_signature` is present, verifier behaves as v0.2 (with a
  diagnostic on stderr indicating the receipt is v0.2-mode).

**Test vectors required:**

- `13-pep-sig-valid/` — pep_signature valid, tags match → PASS.
- `14-pep-sig-missing/` — impact_tags present, pep_signature absent
  → FAIL.
- `15-pep-sig-tag-mismatch/` — pep_signature over a different tag
  set than receipt claims → FAIL.
- `16-pep-sig-empty-tags/` — pep_signature over empty tag set,
  receipt has empty tags → PASS.
- `17-pep-sig-wrong-key/` — signature verifies against a different
  key than `pep_key_id` claims → FAIL.

**Pen-test library additions:**

- `attacks/tag_stripping.py`: upgrade. The v0.2 version is a known
  limit (expects ACCEPT, marked KNOWN_LIMIT). The v0.3 version
  expects REJECT.

**Backwards compatibility.** v0.2 receipts have no `pep_signature`.
Two postures:

- **Strict v0.3 verifier:** rejects v0.2 receipts unless run in
  legacy mode.
- **Default v0.3 verifier:** accepts v0.2 receipts with a stderr
  diagnostic noting they are running at v0.2 conformance (no tag-strip
  protection).

Recommend default v0.3 verifier behavior. Migration aids: a
`--reject-pre-v0.3` flag for deployments ready to enforce strict mode.

**Open design questions:**

- **Q1.** Should `pep_signed_tag_set` include the `id` (receipt ID)
  so the PEP signature is bound to the specific receipt, not just
  the tag set?
  - **Pro:** Prevents replaying a PEP signature across two
    different actions that happen to have the same tag set.
  - **Con:** Forces the PEP into the receipt-issuance pipeline
    (the receipt ID doesn't exist until the receipt is being built).
  - **Lean:** Yes. The PEP is supposed to be in the loop per action;
    binding to receipt ID makes the signature single-use by design.

- **Q2.** Should the PEP signature also bind `context_hash_sha256`?
  - **Pro:** Closes the case where the PEP signs the tag set for
    context A, then the receipt claims context B with the same tags.
  - **Con:** Pushes the PEP into context evaluation, which is
    arguably the PDP's job, blurring the PDP/PEP separation.
  - **Lean:** No. The PEP attests to "the tag set applies to this
    receipt"; the PDP attests to "the verdict applies to this
    context." Keep the roles distinct. Receipt-ID binding (Q1)
    already prevents the cross-receipt replay.

**Estimated total effort:** ~3 days of solo work (spec text,
schema, verifier, vectors, pen-test attack module).

### 6.2 v0.3-2: AUTHZ profile with single-use semantics

**Threats closed:** 6.3.4 (replay in EVIDENCE profile). Resolves held
C-16 and C-17.

**Mechanism.** A second profile alongside EVIDENCE, called AUTHZ. An
AUTHZ-mode receipt represents a single-use authorization claim. The
profile adds:

1. A `nonce` field (UUIDv7, time-ordered for log dedup efficiency).
2. A `single_use: true` marker (explicit, not implied).
3. A MUST that AUTHZ-mode receipts carry `log_inclusion_proof`.
4. A consumer-side obligation: the first verification of a leaf_hash
   in the log is the binding one; subsequent presentations are
   rejected by AUTHZ-mode consumers tracking burnt nonces.

The transparency log is the natural state-keeping mechanism. An
AUTHZ consumer that doesn't want to maintain local state queries
the log for "is this leaf_hash present, and is this the first
presentation I've seen of it?" Local burn-tracking is an
optimization, not a requirement.

This is the Sigstore pattern for code-signing transparency adapted
to action authorization.

**Schema additions:**

```json
{
  "profile": "AUTHZ",
  "nonce": "uuidv7 string",
  "single_use": true
}
```

`profile` is a new top-level field that distinguishes EVIDENCE
(default, retroactive evidence) from AUTHZ (forward, single-use
authorization). EVIDENCE-mode receipts MAY omit the `profile`
field; AUTHZ-mode MUST include it.

**Spec sections affected:**

- §3 conformance: profile-specific rules.
- §4.6: add `profile`, `nonce`, `single_use`.
- New §18: AUTHZ profile semantics (consumer obligations, burn
  tracking, log binding).
- §13 open questions: resolve C-16 and C-17.

**Verifier work:** ~150 LOC.

- Function `verifyAuthzReceipt(receipt, logPublicKey, burnCache)`.
- Burn cache interface: pluggable (in-memory for testing, Redis-
  compatible for production, or "query the log" for stateless).
- Reject if leaf_hash is in burn cache; reject if not in log; accept
  and add to burn cache on first verification.

**Test vectors required:**

- `18-authz-first-use/` — first presentation → PASS.
- `19-authz-replay/` — same receipt, second presentation → FAIL.
- `20-authz-missing-log-inclusion/` — AUTHZ-mode receipt without
  log_inclusion_proof → FAIL.

**Pen-test library:**

- `attacks/replay.py`: upgrade. v0.2 EVIDENCE expects ACCEPT
  (documented limit). v0.3 AUTHZ expects REJECT on the second
  presentation.

**Backwards compatibility.** Pure addition. Existing v0.2 receipts
are EVIDENCE by default. AUTHZ is opt-in.

**Open design questions:**

- **Q1.** Should `single_use: true` be redundant with
  `profile: AUTHZ`?
  - **Pro:** Two ways to express the same thing reduces parsing
    surface.
  - **Con:** Explicit single-use marker is useful even within
    EVIDENCE for some deployment patterns.
  - **Lean:** Keep both. Profile is the conformance hook; single_use
    is the operational hint.

- **Q2.** Can the same nonce be re-used across distinct receipts that
  represent the same logical action?
  - **Lean:** No. Nonce uniqueness is the entire point; if two
    receipts share a nonce, one is a duplicate. Consumer rejects
    both as ambiguous.

**Estimated total effort:** ~4 days.

### 6.3 v0.3-3: Independent evaluation path attestation

**Threats closed:** Detection hook for 6.3.6 (common-mode failure)
and 6.8.5 (common-mode across signers). Does not close, only
detects. The actual closure for poisoned upstream context lives
in §8.1.

**Mechanism.** Every entity that signs (issuer, parent, PDP) declares
the evaluation path it used. The declarations are themselves signed
(implicitly, since they live inside the entity's signed claim).
Monitors and strict verifiers compare path identifiers and flag
collisions.

A path identifier is a structured string describing the reasoning
path:

```
agent:claude-opus-4-2026-05-01:tool-set-cardiology-v3
parent:gpt-5-2026-04-15:cross-check-pipeline-v2
pdp:opa-v0.55:policy-cardiology-prior-auth-v15.3:no-llm
log:redberry-aerf-log-prod:witness-set-A
```

The path identifier is **not** an attestation that the path is
genuinely independent. It is a *declared* description that
allows external observers to detect identity collisions. Real
independence enforcement (e.g., "agent and parent MUST NOT share a
model family") lives in deployment policy, not the spec.

**Schema additions:**

- `parent_evaluation_path_id`: required string when
  `parent_signature` is present. Already optional in v0.2; tighten
  to required.
- `pdp_evaluation_path_id`: required string when `pdp_signature` is
  present.
- `issuer_evaluation_path_id`: optional string at top level.

All three are part of the signed payload (their respective
signatures cover them).

**Spec sections affected:**

- §4.6: tighten optionality on `parent_evaluation_path_id`, add the
  PDP and issuer fields.
- §16: counter-signature semantics: declare that
  `parent_evaluation_path_id` SHOULD differ from
  `issuer_evaluation_path_id`; verifier MUST emit a diagnostic on
  match.
- §17: PDP signature semantics: same for PDP path.
- §12.6 (common-mode failure): rewrite the "detection hooks" paragraph
  to point at v0.3 mechanism.

**Verifier work:** ~40 LOC.

- Diagnostic emission on path-id collision.
- Optional `--require-distinct-paths` flag that promotes the
  diagnostic to a reject.

**Test vectors required:**

- `21-distinct-paths/` — all three path IDs differ → PASS.
- `22-collision-warning/` — agent and parent share path ID, no
  strict flag → PASS with diagnostic.
- `23-collision-strict/` — same, with strict flag → FAIL.

**Pen-test library:**

- `attacks/common_mode.py`: upgrade from KNOWN_LIMIT marker to
  expected behavior under strict mode (REJECT) and non-strict
  (ACCEPT with diagnostic).

**Backwards compatibility.** v0.2 receipts have no required PDP path
ID. Verifier in v0.3 default mode emits an informational diagnostic
("no PDP evaluation path declared") and continues. Strict mode
rejects.

**Open design questions:**

- **Q1.** Is the path ID format normative or free-form?
  - Free-form is easier to ship; normative makes monitor logic
    portable across deployments.
  - **Lean:** Free-form for v0.3, with a non-normative recommended
    structure (`<role>:<model_or_engine>:<config_version>:<flags>`).
    Promote to normative in v1.0 if usage converges.

- **Q2.** Should the path ID itself be a hash of an external
  attestation (e.g., a signed model card)?
  - This is the natural step-up: instead of declaring a path, prove
    the path with an external attestation chain.
  - **Lean:** Out of scope for v0.3. Future work, possibly
    composition with model-card attestations.

**Estimated total effort:** ~2 days.

### 6.4 v0.3-4: Conformant log registry

**Threats closed:** 6.7.2 (conformant-log registry capture, currently
future work). Strengthens 6.2.2, 6.2.3, 6.2.4 by making log
selection less ad hoc.

**Mechanism.** A public registry of logs meeting the §15 conformance
criteria. Each registry entry includes:

```yaml
log_id: "redberry-aerf-prod-001"
url: "https://log.redberry.example.com/aerf"
public_key: "<base64 SPKI PEM>"
mmd_seconds: 3600
witness_set:
  - witness_id: "witness-eu-1"
    public_key: "..."
  - witness_id: "witness-na-1"
    public_key: "..."
quorum_n_of_m: [2, 2]
sla:
  read_api_uptime_pct: 99.9
  monitor_cadence_seconds: 1800
key_rotation_policy: "annual; emergency rotation on disclosure"
operator: "Redberry Labs, Inc."
contact: "log-ops@redberry.example.com"
registered_at: "2026-07-01T00:00:00Z"
```

Receipts referencing logs **not in the registry** are accepted at
the base profile but rejected at the production profile.

Governance starts simple: a signed Git repository under the
`aerf-spec` GitHub organization, with the registry maintained by the
editor and a small set of contributors. Each registry-edit commit
must be signed by ≥2 contributors. Mirror the registry into AERF's
own transparency log (log-of-logs) for self-auditability.

When AERF adoption justifies a working group, governance escalates
to multi-stakeholder. Until then, the editor publishes a public
intake process.

**Spec sections affected:**

- §15: add normative registry reference.
- §3 conformance: production profile requires registry-listed log.
- New `docs/REGISTRY-GOVERNANCE.md`.

**Verifier work:** ~60 LOC.

- Bundled registry snapshot fetched at build time (verifiers ship
  with a known-good snapshot).
- `--registry <path>` flag to override.
- Reject in production profile if log_id is not in registry.

**Test vectors required:**

- `24-registry-listed-log/` — log_id present in bundled registry
  snapshot → PASS in production.
- `25-registry-unknown-log/` — log_id absent → FAIL in production,
  PASS in base.

**Backwards compatibility.** v0.2 receipts that referenced ad hoc
logs migrate to production profile when those logs are registered.
Existing deployments running their own logs need to either submit
for registry inclusion or run in base profile.

**Open design questions:**

- **Q1.** How does the registry handle log key rotation?
  - **Lean:** Registry entries carry a key history. Receipts
    reference the log_id; the verifier resolves to the appropriate
    key based on the receipt's timestamp.

- **Q2.** Vendor / private logs (not publicly readable)?
  - For HIPAA deployments, the log itself may be confidential. The
    registry could carry private-log entries with restricted-access
    metadata.
  - **Lean:** v0.3 ships public-log support only. Private-log
    semantics are v1.0 work.

**Estimated total effort:** ~5 days, mostly governance documentation
and intake process work rather than code.

### 6.5 v0.3-5: Witness quorum normative spec

**Threats closed:** 6.4.2 (split-view), 6.4.3 (backdated), 6.4.5 (log
key compromise), 6.7.3 (witness collusion).

**Mechanism.** Replace v0.2's informational "≥2 witnesses
recommended" with a normative quorum policy carried by the
conformant-log registry entry. Each receipt's `log_inclusion_proof`
MUST be cosigned by N of M witnesses from the registered witness
set, where N and M are properties of the log's registry entry.

Witness selection criteria, normative:

- Administratively independent from the log operator and from each
  other (different legal entities, different management, different
  funding sources).
- Geographically distributed where feasible.
- Independent key generation and rotation.
- Each witness operates its own monitor that retrieves STHs at
  ≤MMD cadence and publishes consistency proofs.

**Schema additions:** none. The witness cosigs already exist in
v0.2's `log_inclusion_proof`. v0.3 adds the quorum check to the
verifier, not to the wire format.

**Spec sections affected:**

- §15: replace "SHOULD ≥2" with quorum-from-registry semantics.
- §10.1 verification procedure: add witness quorum check.

**Verifier work:** ~40 LOC.

- Witness cosig collection in `log_inclusion_proof.sth_cosigs[]`.
- Quorum check: count valid cosigs against registered witness keys;
  reject if below N.

**Test vectors required:**

- `26-quorum-met/` — 2-of-2 witnesses cosigned → PASS.
- `27-quorum-missed/` — 1-of-2 → FAIL in production.
- `28-cosig-by-non-witness/` — cosig from a key not in witness set
  → ignored, quorum may still fail → FAIL.

**Backwards compatibility.** v0.2 receipts with single-witness logs
move to base profile. To stay production-conformant, deployments
need their logs to register multi-witness quorums.

**Open design questions:**

- **Q1.** Default quorum size?
  - **Lean:** 2-of-3 for production. Below that, base profile.
    Higher quorums per deployment policy.

- **Q2.** What happens if a witness key is rotated mid-receipt-life?
  - **Lean:** Witness key history in registry; cosig valid if signed
    by any key in the witness's history that was active at the STH's
    timestamp.

**Estimated total effort:** ~3 days.

### 6.6 v0.3-6: Receipt ID format upgrade (UUIDv7)

**Threats closed:** Strengthens 6.3.4 (replay) and log dedup
performance. Resolves held C-15.

**Mechanism.** Change `id` from UUIDv4 to UUIDv7 (RFC 9562). UUIDv7
embeds a millisecond timestamp in the high bits, giving time-ordered
IDs that are still globally unique. This makes log dedup (a B-tree
or LSM index over IDs) O(log n) instead of O(n) for time-windowed
queries.

Content-addressed IDs (hash of the canonical payload) were
considered. They create a chicken-and-egg problem with the chain
hash (the ID can't be in the signed payload if it's derived from
the payload), solvable by treating the content-addressed ID as a
derived property rather than a stored field. This is a deeper
change and probably v1.0 work.

**Schema additions:** pattern change on `id` field from UUIDv4 to
UUIDv7. New `^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`.

**Spec sections affected:**

- §4.2: update `id` pattern and description.
- §13: resolve C-15.

**Verifier work:** ~10 LOC. Pattern update.

**Test vectors required:**

- Update existing vectors to use UUIDv7 IDs.
- `29-uuidv4-rejected/` — legacy UUIDv4 receipt → FAIL in v0.3,
  PASS in legacy mode.

**Backwards compatibility.** v0.2 receipts use UUIDv4. Verifier in
v0.3 default mode accepts both with a diagnostic on UUIDv4; strict
mode rejects UUIDv4.

**Estimated total effort:** ~1 day.

### 6.7 v0.3-7: Cross-role key reuse becomes MUST reject

**Threats closed:** 6.6.2 (cross-role key reuse).

**Mechanism.** §10.1 currently says verifier SHOULD warn on key_id
collision across roles (issuer, parent, PDP, PEP, log, witnesses).
Upgrade to MUST reject. CR-3 (assumption that keys are independent)
becomes mechanically enforced rather than honor-system.

**Schema additions:** none.

**Spec sections affected:**

- §10.1: upgrade SHOULD to MUST.
- §12 security considerations: cross-reference CR-3 closure.

**Verifier work:** ~5 LOC. Replace warning with rejection.

**Test vectors required:**

- `30-key-id-collision/` — same key_id used for issuer and parent
  → FAIL.

**Backwards compatibility.** Deployments that accidentally reuse
keys across roles break under v0.3. This is intentional; it is the
defect this item closes.

**Estimated total effort:** ~0.5 days.

### 6.8 v0.3-8: Normative key transport mechanism

**Threats closed:** Reduces OP-1 (verifier key acquisition) burden.
Resolves held C-10.

**Mechanism.** Define a normative way to publish and discover the
public keys referenced by `key_id` values. Three candidates:

| Candidate | Pros | Cons |
|---|---|---|
| **JWK Set at well-known URL** (e.g., `https://<issuer>/.well-known/aerf-jwks.json`) | Ecosystem alignment (JWT/OIDC world). Simple HTTP fetch. Cache-friendly. | Issuer DNS becomes a dependency. No revocation built-in. |
| **DID documents** (W3C DID Core, with did:web or did:key resolvers) | Decentralized. Native key rotation semantics. | More complex resolver chain. Smaller ecosystem in the regulated-industry space. |
| **Sigstore Fulcio-style** (short-lived keys bound to OIDC identity) | No long-term key management. Strong identity binding. | Requires Fulcio infrastructure. Issuer identity becomes OIDC subject, which may not match the deployment's identity model. |

**Recommendation:** JWK Set at well-known URL as the normative
mechanism for v0.3. DID and Fulcio as optional profiles.

The JWK Set is hosted at `https://<issuer-domain>/.well-known/aerf-jwks.json`
and contains all keys an issuer may use: issuer key, agent keys,
parent keys, PDP keys, PEP keys. Each entry includes its `key_id`
(matching the receipt's field) and SPKI PEM.

For the parent / PDP / PEP keys that belong to a *different*
administrative domain than the issuer, the receipt MAY include a
`<role>_key_url` field pointing to the relevant JWK Set.

**Schema additions:**

```json
{
  "issuer_key_url": "https://issuer.example.com/.well-known/aerf-jwks.json",
  "parent_key_url": "https://parent-org.example.com/.well-known/aerf-jwks.json",
  "pdp_key_url": "...",
  "pep_key_url": "...",
  "log_key_url": "..."
}
```

All optional; if absent, verifier uses out-of-band key provisioning.

**Spec sections affected:**

- New §19: Key transport.
- §4.6: add the `<role>_key_url` fields.
- §10.1: optional fetch-and-cache step before verification.

**Verifier work:** ~120 LOC.

- HTTP fetcher with TLS verification and HSTS preload.
- JWK Set parser.
- Key cache with TTL.
- `--no-fetch` flag for air-gapped environments.

**Test vectors required:**

- `31-jwks-fetch-success/` — verifier fetches a fixture JWK Set and
  validates → PASS. (Uses a local fixture server.)
- `32-jwks-fetch-failure/` — JWK Set URL unreachable → FAIL with
  specific reason code.

**Backwards compatibility.** Pure addition. Receipts without
`<role>_key_url` fields still verify via out-of-band keys.

**Open design questions:**

- **Q1.** Should the JWK Set itself be signed (e.g., by a
  long-term root key)?
  - **Pro:** Closes a class of DNS / TLS compromise attacks against
    the issuer domain.
  - **Con:** Adds key-of-keys complexity.
  - **Lean:** Out of scope for v0.3. Note as v1.0 direction.

- **Q2.** Revocation?
  - **Lean:** Defer to v1.0. The transparency log makes revocation
    less urgent since the timestamp anchors validity.

**Estimated total effort:** ~5 days.

---

## 7. v1.0+ directional items

Less detailed than v0.3 items. Each is a direction, not a
specification.

### 7.1 BBS+ / ZK profiles for selective disclosure

**Threats addressed:** Privacy of context. Not a threat-model entry
per se, but a recurring buyer ask in regulated industries.

**Direction.** Two complementary mechanisms:

- **BBS+ signatures over context.** Issuer signs a receipt where the
  context is committed to via a BBS+ scheme. Verifier can request a
  predicate proof (e.g., "patient_age > 18") without learning the
  full context. Requires switching some receipt fields from Ed25519
  to BBS+.

- **ZK-SNARK proofs of policy compliance.** Prover generates a
  succinct proof that "the agent's action satisfies policy P under
  some context C whose hash is H," without revealing C. Heavyweight
  but real; lineage in private credentials and zkPass.

Composition with v0.3 receipts: the receipt carries a
`disclosure_proof` field referencing the external BBS+ or ZK proof.

**Open question:** which primitive ships first. BBS+ is the
lighter-weight choice and is in active standardization.

### 7.2 Hardware-backed signing as a profile

**Threats addressed:** Strengthens A4 resistance (compromised
issuer). Currently profile P-1 in v0.2 (TEE attestation, named not
specified).

**Direction.** Profile P-1 receipts include `key_attestation` fields
referencing hardware-trust-rooted attestation chains:

- AWS Nitro Enclave attestation documents.
- Google Confidential Computing attestation.
- Intel TDX / SGX attestation chains.
- HSM PKCS#11 attestation.

Each signing key in the receipt (issuer, parent, PDP, PEP) declares
its hardware provenance separately. Verifier accepts profile P-1 only
if all signing keys carry valid attestation chains rooted in
deployment-trusted CAs.

**Open question:** which hardware platforms become normatively
specified vs. extensible.

### 7.3 Content-addressed receipt IDs

**Direction.** Replace UUIDv7 (v0.3) with content-addressed IDs in
v1.0. Receipt ID becomes SHA-256 of the canonical payload. Requires
treating ID as a derived property rather than a stored field, with
schema-level handling for the chicken-and-egg with chain hash.

Benefit: self-verifying IDs, no separate dedup index needed.

---

## 8. Composition patterns (out of scope, addressable upstream)

These threats are not closeable within AERF. They are addressable by
composing AERF receipts with other formats. The pattern below
defines what AERF needs to expose to enable composition; the
upstream formats do their own job.

### 8.1 Context provenance

**Threats addressed:** 6.8.1 (prompt injection), 6.8.2 (tool
poisoning), 6.8.3 (memory contamination), 6.8.4 (retrieval
poisoning), 6.8.5 (common-mode across signers).

**Pattern.** AERF receipts carry a `context_provenance` array
referencing external attestations covering the agent's input context.
AERF does not subsume these formats; it records that they existed
and what they attested to.

```json
{
  "context_provenance": [
    {
      "kind": "in-toto",
      "predicate_type": "https://slsa.dev/provenance/v1",
      "subject_hash": "sha256:...",
      "attestation_uri": "https://attestations.example.com/...",
      "attestation_hash": "sha256:..."
    },
    {
      "kind": "c2pa",
      "manifest_hash": "sha256:...",
      "asset_uri": "ipfs://..."
    },
    {
      "kind": "retrieval",
      "vector_store_snapshot_hash": "sha256:...",
      "retrieved_at": "2026-05-11T17:42:03Z",
      "documents": [
        { "uri": "...", "content_hash": "sha256:..." }
      ]
    },
    {
      "kind": "tool_output",
      "tool_id": "ehr-fhir-query",
      "tool_signature": "hex ed25519",
      "tool_key_id": "..."
    }
  ]
}
```

This is a passthrough field. The verifier does not validate the
content of context_provenance entries; it canonicalizes them as part
of the receipt's signed payload and records their presence. Downstream
auditors validate them against the relevant external schema.

**Spec section:** new §20 in v0.3 or v1.0.

**Composition partners worth naming:**

- **in-toto / SLSA** for build, config, and policy supply chain.
  Receipt records a SLSA provenance attestation hash; SLSA verifier
  validates the build chain.
- **C2PA** for media inputs (images, video, audio). Receipt records a
  C2PA manifest hash.
- **Emerging retrieval attestation patterns** (vector store integrity,
  signed RAG corpus snapshots). No mature standard exists yet; AERF's
  `context_provenance` field gives a place to put one when it
  emerges.
- **Tool-output signatures.** Tools that return data sign their
  outputs with their own keys (PKCS#11 / Ed25519). The agent's
  context_hash transitively covers these because the signed tool
  output is part of what the agent saw.

**Practical posture.** v0.3 ships the `context_provenance` field as
a typed passthrough. AERF doesn't promise that any composition
partner is integrated; deployments choose which formats to attach.

### 8.2 Verifier key acquisition

See §6.8 (v0.3-8). The composition pattern is JWK Set at
well-known URL, with DID and Fulcio as optional profiles.

### 8.3 Hardware key isolation

See §7.2. The composition pattern is hardware attestation chains
referenced from a `key_attestation` field in profile P-1.

### 8.4 Privacy / selective disclosure

See §7.1. The composition pattern is BBS+ for predicate proofs and
ZK-SNARK for arbitrary policy compliance proofs, with the AERF
receipt carrying a `disclosure_proof` reference.

---

## 9. Operational guidance (not spec changes)

A handful of threats are mitigated by deployment posture rather than
spec mechanism. These belong in a `docs/DEPLOYMENT-GUIDE.md` rather
than `SPEC.md`. Listed here so the threat coverage is complete.

| Threat | Operational mitigation |
|---|---|
| 6.6.3 weak RNG / shared seed | Use platform-provided CSPRNG; require independent HSM partitions per role; smoke-test key uniqueness at provisioning. |
| 6.9.1 parent DoS | Configure verifier to fail closed on missing parent_signature for HIGH-IMPACT actions. Run parent agents in HA pairs. |
| 6.9.2 MMD-window evasion | Monitor log retrieval is itself monitored; outages exceeding MMD page on-call. |
| OP-3 monitoring | Contractual SLA with monitor operator; or deploy own monitor; or rely on registry-listed monitor for the chosen log. |
| OP-4 path independence | Deployment policy must specify which path-ID combinations count as "genuinely independent." AERF v0.3-3 surfaces collisions; policy enforces. |
| OP-5 PEP tag pinning | Audit deployment architecture for where tags are assigned. v0.3-1 mechanically enforces this once it ships. |

---

## 10. Cryptographically irreducible

No engineering path closes these at the receipt layer. The
appropriate response is acknowledgment plus operational depth.

| Item | Why irreducible | Operational depth |
|---|---|---|
| Quorum compromise (A11) | All keys held by adversary; nothing the protocol can do | Transparency log preserves the receipts permanently for forensic detection; key rotation limits rolling exposure |
| Ed25519 EUF-CMA failure | Primitive failure of the digital signature scheme | Adopt post-quantum signing primitives when standardized (NIST PQC track); profile work for v2.0+ |
| SHA-2 collision | Primitive failure of the hash | Same; adopt SHA-3 family in a future profile |
| RNG compromise | Key generation breakdown | Operational; HSM-backed key generation, independent entropy sources |
| Side-channel on signing device | Hardware attack | Profile P-1 (hardware attestation) + HSM deployment |

These are not unique to AERF. Every cryptographic protocol carries
the same residuals. Mention is for completeness, not because AERF
has a worse posture than peers.

---

## 11. Prioritization and sequencing

Order by threat severity × doability × dependency.

### Tier 1: ships in v0.3.0-draft.1 (next major draft)

1. **v0.3-1 PEP-side tag signing.** Closes the most serious documented
   limit. ~3 days. Self-contained.
2. **v0.3-7 cross-role key reuse rejection.** Cheapest win. ~0.5 days.
3. **v0.2 patch 5.1** normative timestamps for production. ~0.5 days.
4. **v0.2 patch 5.2** witness count SHOULD ≥ 2. ~0.5 days.

Tier 1 total: ~4.5 days of solo work. This is the highest-value batch.

### Tier 2: ships in v0.3.0-draft.2

5. **v0.3-5 witness quorum normative spec.** Builds on patch 5.2. ~3 days.
6. **v0.3-3 evaluation path attestation.** Detection layer for
   common-mode. ~2 days.
7. **v0.3-4 conformant log registry.** Governance work, ~5 days but
   mostly non-code.

Tier 2 total: ~10 days, with the registry being the long pole.

### Tier 3: ships in v0.3.0 final

8. **v0.3-2 AUTHZ profile.** Important for chain-of-custody use cases.
   ~4 days.
9. **v0.3-8 key transport.** JWK Set at well-known URL. ~5 days.
10. **v0.3-6 UUIDv7.** ~1 day.

Tier 3 total: ~10 days.

### Tier 4: v1.0+ profile work

- §7.1 selective disclosure profile.
- §7.2 hardware attestation profile.
- §7.3 content-addressed IDs.

Each is a multi-week design effort with substantive open questions.
Not prioritized here.

### Composition work

- §8.1 `context_provenance` passthrough field can land in v0.3.0-draft.1
  cheaply; the field is a passthrough with no validation, so the
  cost is schema + spec text only (~1 day). Ships in Tier 1 if
  schedule permits.

### Total v0.3 effort

~25 days of solo focused work, plus ~10 days for governance
(registry intake process, contributor coordination), plus ~5 days
slack. Call it 6 weeks of calendar time at solo founder rates with
GTM work running in parallel.

---

## 12. What this plan does not promise

To match the threat model's honesty about residuals.

- **It does not close A11.** Quorum compromise of the upstream
  signing set produces valid-looking receipts. The transparency log
  preserves them for forensic detection; that is the only useful
  property at full quorum.
- **It does not solve upstream context.** The §8.1 composition
  pattern records that external attestations existed; it does not
  validate them. The actual closure for A10 lives in whatever
  upstream provenance format the deployment chooses.
- **It does not specify post-quantum migration.** When NIST PQC
  signing schemes ship (ML-DSA, SLH-DSA), a future profile adds them.
  v0.3 stays on Ed25519.
- **It does not standardize the path-ID format normatively.** v0.3-3
  uses free-form path IDs with a recommended structure. Normative
  format is v1.0 work.
- **It does not address GDPR right-to-erasure on the transparency
  log.** Append-only logs and erasure rights are in tension; the
  intersection is its own design problem. Composition with
  redaction-aware logs is a v1.0 direction.

---

## 13. Reviewer ask

If you are reviewing this plan, the questions that benefit most from
external eyes:

1. **v0.3-1 Q1 (PEP signature binds receipt ID).** Is the PEP-in-loop
   pattern operationally realistic in regulated deployments? The
   PDP/PEP split is XACML lineage; in practice, are they often
   collocated to the point that this distinction is theater?
2. **v0.3-3 path-ID format.** Free-form vs. normative. The lean is
   free-form for v0.3; is there an argument for normative now to
   avoid format fragmentation?
3. **v0.3-4 registry governance.** Editor-curated Git repo is the
   right v0.3 posture; when should escalation to a multi-stakeholder
   working group happen, and what would trigger it?
4. **§8.1 context_provenance.** Is the passthrough design the right
   call, or should AERF actually validate at least one upstream
   format normatively (most likely SLSA provenance)?
5. **§7.1 selective disclosure direction.** BBS+ first vs. ZK-SNARK
   first vs. ship both as parallel optional profiles?
6. **Tier 1 vs Tier 2 cut.** Anything I have in Tier 2 or 3 that
   should bump to Tier 1, or vice versa?

Specific, scoped questions are better than open-ended review. If you
disagree with a disposition (e.g., I have something as "irreducible"
that you think is closeable), the right artifact to push back on is
the relevant subsection here, not the threat model.

---

## 14. References

- `THREAT-MODEL.md` (companion document).
- `SPEC.md` v0.2.0-draft.1.
- `DECISIONS.md` for locked and held decisions.
- RFC 8032 (Ed25519), RFC 8785 (JCS), RFC 9162 (CT v2), RFC 9562
  (UUID), RFC 3161 (timestamps).
- SLSA v1.0, in-toto attestation framework, C2PA technical
  specification.
- W3C DID Core, W3C Verifiable Credentials (informational reference
  for selective disclosure).
- Sigstore architecture (Rekor, Fulcio).
- BBS+ signatures (draft-irtf-cfrg-bbs-signatures).

---

*End of RESOLUTION-PLAN.md. Aligned with `THREAT-MODEL.md` and
`SPEC.md` v0.2.0-draft.1.*
