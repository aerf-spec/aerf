# AERF v0.2 — Threat Model

> **Status:** Companion to `SPEC.md` v0.2.0-draft.1. Not normative. The
> spec defines what conformant implementations do; this document
> explains what they defend against and what they do not.
>
> **Editor:** Aniketh Maddipati. **Reviewers welcome.** C-12 reported by
> John Truong.

---

## 1. Scope and method

### 1.1 What this document is

A structured analysis of the threats AERF v0.2 is designed to defend
against, the defenses each threat is mapped to, and the residual risks
the spec does not close. It is the artifact that justifies the v0.2
design choices, particularly the C-12 resolution.

It exists so that:

- Implementers can verify they have wired up the right defenses.
- Auditors and verifiers can see which guarantees a receipt actually
  buys at each conformance level.
- Future contributors can argue against the design without having to
  reconstruct the threat surface from scratch.
- Procurement and compliance reviewers can locate exactly what the
  spec does and does not promise.

### 1.2 What this document is not

- A compliance attestation. AERF is a wire format and a verifier; it
  does not assert HIPAA, SOC 2, or ISO 42001 compliance for any
  deployment. The framework mapping pages under `docs/frameworks/`
  describe how AERF receipts contribute evidence to specific
  controls.
- A deployment security audit. Threats that depend on specific
  hardware (HSMs, TEEs), specific network configurations, or specific
  operational practices are out of scope unless the spec mandates a
  control over them.
- A guide to securing the agent itself. AERF records what the agent
  did and what policy applied; preventing the agent from doing the
  wrong thing is the runtime's job. The receipt is evidence, not
  enforcement.

### 1.3 Method

Adapted STRIDE per system entity, plus an attack catalog organized by
attack surface. Each attack entry carries:

- **Adversary capability required** to mount it.
- **Detection layer** in the v0.2 spec that catches it.
- **Residual risk** if the detection layer is itself defeated or
  absent.
- **Status:** mitigated, mitigated-with-caveats, documented limit, or
  out of scope.

The vocabulary throughout is that of cryptographic protocol design:
adversaries have explicit capabilities, defenses have explicit
preconditions, and "trust" is decomposed into the specific
cryptographic and operational assumptions it stands on.

### 1.4 Conventions

RFC 2119 capitals refer to the spec, not this document. References to
sections (§N.M) are to `SPEC.md`. Decision identifiers (C-N) are from
`DECISIONS.md`.

---

## 2. System model

### 2.1 Entities

An AERF deployment in the v0.2 model involves the following entities.
Not every deployment uses all of them; the spec's `MUST`/`SHOULD`
rules track presence/absence.

| Entity | Role | Holds key? |
|---|---|---|
| **Issuer** | Notary infrastructure that signs receipts on behalf of an agent. The cryptographic origin of `signature`. | Yes (issuer key) |
| **Agent** | The software actor whose actions are being notarised. | Optional (`agent_signature` if dual control) |
| **Parent agent** | A higher agent in a multi-agent topology that counter-signs receipts originating from a child. | Yes (parent key) |
| **PDP** (Policy Decision Point) | An independently-keyed evaluator that signs the verdict tuple `(context_hash_sha256, policy_hash, in_policy)`. | Yes (PDP key) |
| **PEP** (Policy Enforcement Point) | The component that decides whether to take the action given the PDP's verdict. Does not sign anything in v0.2. | No |
| **Transparency log** | An append-only Merkle log to which receipts (or their leaf hashes) are submitted. | Yes (log key for STH) |
| **Witness** | A third party that co-signs the log's STH to detect split-view. | Yes (witness key) |
| **Monitor** | A passive observer of the log, watching for invariant violations (consistency proofs, MMD, expected entries). | No |
| **Verifier** | A party who checks a receipt's claims given the relevant public keys. | No |
| **Auditor** | A specialized verifier with retrospective scope (chains, log inclusion, common-mode analysis). | No |

The lineage is XACML for PDP/PEP, RFC 6962/9162 for the log/witness
pattern, and Sigstore/Rekor for the agent-action transparency
posture.

### 2.2 Trust boundaries

The boundaries that matter for this threat model:

```
                        +- - - - - - - - - - - - - - - +
                        : Upstream context provenance  :   <-- OUT OF SCOPE
                        : (prompt source, retrieval,   :       (residual §10.1)
                        :  tool outputs, memory)       :
                        +- - - - - - - - - - - - - - - +
                                       |
                                       v
              +------------------+   tools / context   +-------------------+
              |  Agent runtime   | <-----------------> |   External world  |
              +--------+---------+                     +-------------------+
                       |
                       v
   +---+ build receipt +---+   sign    +-----------+  publish  +-------------+
   |   |-------------->|   |---------->|  Issuer   |---------->|  Log        |
   |Agt|               |Iss|           |  Ed25519  |           |  (RFC 9162) |
   +---+               +---+           +-----------+           +------+------+
                          ^                                            |
                          | bind                                       |
                          |                                          witness
                          v                                            |
                       +-----+   bind   +-----+                        v
                       | PDP |--------->| Plan|                  +----------+
                       +-----+          +-----+                  | Witness  |
                                                                 +----------+
                          ^
                          | counter-sign
                          |
                       +--------+
                       | Parent |
                       +--------+

                       +----------+   verify   +----------+
                       | Verifier |<-----------| Receipt  |
                       +----------+            +----------+
```

The diagram is informational. The boundaries the spec actually
defends are:

1. **Issuer ↔ verifier:** the Ed25519 signature on the canonical
   payload (§7, §10.1 step 5).
2. **Issuer ↔ chain:** `previous_receipt_hash` pinning (§8).
3. **Issuer ↔ parent agent:** `parent_signature` over the receipt
   (§4.6, §16).
4. **Issuer ↔ PDP:** `pdp_signature` over `(context_hash_sha256,
   policy_hash, in_policy)` (§4.6, §17).
5. **Issuer ↔ log:** `log_inclusion_proof` against an STH (§15).

Boundaries the spec **does not** defend:

- **Upstream context ↔ agent.** AERF binds via `context_hash_sha256`;
  it does not attest provenance of the context itself. Residual
  documented in §12.6 of the spec and §10.1 below.
- **Verifier's key acquisition.** Standard PKI problem; not solved
  by AERF.

### 2.3 Data flow assumptions

- The receipt and any associated proofs travel together as a single
  artifact.
- Receipts may be retained indefinitely. There is no expiration
  semantic in the EVIDENCE profile (locked C-16).

---

## 3. Adversary capability profiles

| ID | Adversary | Capabilities |
|---|---|---|
| **A1** | Network attacker (Dolev-Yao) | Read, modify, drop, replay, reorder messages. No key access. |
| **A2** | Malicious verifier | Public keys only. No signing key access. |
| **A3** | Compromised lower agent | Holds the agent's signing key. **The C-12 adversary.** |
| **A4** | Compromised issuer | Issuer signing key. |
| **A5** | Compromised parent | Parent signing key. |
| **A6** | Compromised PDP | PDP signing key. |
| **A7** | Compromised log operator | Log STH-signing key. |
| **A8** | Compromised witness | Witness cosig key. |
| **A9** | Compromised registry editor | Commit access to the impact-tag or conformant-log registry. |
| **A10** | Upstream context attacker | Poisons input context. No key access at the AERF layer. |
| **A11** | Quorum compromise | Two or more keys from {agent, issuer, parent, PDP, log, witness}. |

The C-12 closure forces A3 to combine with A5, A6, or A7 to produce
a false truth claim that survives verification.

---

## 4. Assumptions

### 4.1 Cryptographic assumptions

| ID | Assumption | If it fails |
|---|---|---|
| **CR-1** | Ed25519 (RFC 8032) is EUF-CMA secure. | All signature claims collapse. |
| **CR-2** | SHA-256 / SHA-512 (FIPS 180-4) are collision-resistant. | Chain integrity collapses. |
| **CR-3** | Independent keys remain independent in practice. | Multi-key requirements collapse to single-key. |
| **CR-4** | RFC 8785 canonicalization is deterministic under our additional NFC + string-numbers constraints. | Encoding ambiguity attacks possible. |
| **CR-5** | RFC 3161 TSAs sign honestly, or multi-TSA configuration. | Backdating defenses fail. |

### 4.2 Operational assumptions

| ID | Assumption | If it fails |
|---|---|---|
| **OP-1** | Verifiers obtain the correct public keys. | A1 + bad key delivery becomes forgery. |
| **OP-2** | Receipt recipients have a known clock skew bound. | Timing attacks against MMD become possible. |
| **OP-3** | Log is watched by ≥1 independent monitor at ≤MMD cadence. | Log degrades to "tamper-evident but undetected." |
| **OP-4** | Parent and PDP evaluation paths are genuinely independent. | Common-mode failure. |
| **OP-5** | Impact tags are pinned by the PEP before issuer signs. | Tag stripping trivially bypasses sync counter-sign. |

### 4.3 Governance assumptions

| ID | Assumption | If it fails |
|---|---|---|
| **GV-1** | Impact-tag core registry is closed in v0.2; changes via spec revision. | Mitigated by closed-set design (registry is normative-text-in-spec). |
| **GV-2** | Vendor-namespace tags interpreted only by deployments that recognize them. | Tag pollution stays local to one deployment. |
| **GV-3** | Future conformant-log registry curated such that listed logs satisfy §15. | Out of scope for v0.2. |

---

## 5. Asset inventory

### 5.1 Primary assets

| Asset | What protects it | Failure mode |
|---|---|---|
| Receipt authenticity | `signature` (Ed25519 over canonical payload) | A4 |
| Receipt integrity | Same signature | A4 |
| Receipt truth | `parent_signature` + `pdp_signature` together | A3 ∧ A5; A3 ∧ A6; A10 (residual) |
| Receipt order | `previous_receipt_hash` chain (C-7, C-24) | A4 + rotation; collision-resistance failure |
| Receipt non-omission | Transparency log inclusion + witness cosig | A7 ∧ A8 |
| Receipt freshness | RFC 3161 trusted timestamp + log STH timestamp | A4 ∧ A7 |
| PDP verdict integrity | `pdp_signature` over bound tuple | A6 |
| Action-context binding | `context_hash_sha256` cross-binding | A6 ∧ A3; A10 (residual) |

### 5.2 Secondary assets (key material)

Issuer key, agent key, parent key, PDP key, log STH key, witness
keys, TSA CA chain. CR-3 requires independent generation per role.
Recommended posture: one HSM partition per role for the high-impact
path.

---

## 6. Attack catalog

### 6.1 Receipt-level attacks

#### 6.1.1 Plain forgery

- **Capability:** A1.
- **Detection:** §10.1 step 5.
- **Residual:** Bad key acquisition (OP-1).
- **Status:** mitigated.

#### 6.1.2 Field tampering after issuance

- **Capability:** A1.
- **Detection:** Signature covers every field except the
  post-issuance strip set (§8.4 / C-24).
- **Status:** mitigated. Demonstrated by
  `verifiers/go/example/receipt-tampered.json`.

#### 6.1.3 Schema confusion via additional fields

- **Capability:** A1 or A4.
- **Detection:** Unknown fields are decorative under EVIDENCE; no
  normative effect on verification.
- **Status:** mitigated by spec.

#### 6.1.4 Malformed receipt

- **Detection:** Schema validation; pattern checks for hex / UUID
  shapes.
- **Status:** mitigated.

#### 6.1.5 Signature malleability

- **Detection:** Ed25519 signatures are deterministic; non-canonical
  encodings rejected by RFC 8032 verification.
- **Status:** mitigated by primitive choice.

#### 6.1.6 Hash length-extension

- **Status:** not applicable to AERF's use of SHA-2.

### 6.2 Chain-level attacks

#### 6.2.1 Reorder

- **Detection:** Each `previous_receipt_hash` pins the predecessor.
- **Status:** mitigated.

#### 6.2.2 Skip a link

- **Detection:** Predecessor hash check; log makes existence
  checkable.
- **Status:** mitigated with log; detection-only without.

#### 6.2.3 Genesis spoof

- **Detection:** §8.1 / C-6; log catches "genesis" at position N>1.
- **Status:** mitigated with caveats.

#### 6.2.4 Fork

- **Detection:** Two leaves with the same `previous_receipt_hash`
  visible to the log.
- **Status:** mitigated by log.

#### 6.2.5 Re-sign with rotated key

- **Detection:** Trusted timestamp + log STH timestamp.
- **Status:** mitigated in production profile.

### 6.3 Multi-agent attacks (the C-12 family)

#### 6.3.1 Compromised child issues false truth claim (C-12 base)

- **Capability:** A3.
- **Detection (v0.2):** Layered. (i) HIGH-IMPACT actions require
  `parent_signature` — adversary needs A3 + A5. (ii) HIGH-IMPACT
  actions require `pdp_signature` bound to `(context_hash_sha256,
  policy_hash, in_policy)` — adversary needs A6. (iii) Log inclusion
  makes any false claim permanently visible.
- **Residual:** A3 + A5 + A6 (full upstream-quorum compromise).
- **Status:** mitigated for A3 alone; mitigated-with-detection for
  partial quorum; documented limit for full quorum.

#### 6.3.2 Tag stripping at receipt layer

- **Capability:** A3.
- **Detection:** None at receipt layer. Defense is upstream PEP
  (OP-5).
- **Status:** documented limit (§12.7).

#### 6.3.3 Split-context attack

- **Capability:** A3.
- **Detection:** `pdp_signature` binds `context_hash_sha256` and
  `policy_hash`; verifier re-canonicalizes and matches.
- **Residual:** A3 + A6 collusion.
- **Status:** mitigated for A3 alone.

#### 6.3.4 Replay of a child's old valid receipt

- **Detection:** Receipt `id`, `observed_at`, log inclusion
  timestamp. EVIDENCE profile has no replay token (C-16).
- **Status:** documented limit; AUTHZ profile (held C-17) addresses.

#### 6.3.5 PDP bypass on a HIGH-IMPACT action

- **Detection:** §3 conformance step: missing `pdp_signature` with
  non-empty `impact_tags` is a rejection.
- **Status:** mitigated.

#### 6.3.6 Parent counter-sign on shared poisoned context (common-mode)

- **Capability:** A10.
- **Detection:** None at the receipt layer.
- **Hooks:** `parent_evaluation_path_id`, context-hash distribution
  monitoring.
- **Status:** documented limit (§12.6).

### 6.4 Transparency log attacks

#### 6.4.1 Log omission

- **Detection:** Missing `log_inclusion_proof` fails closed.
- **Status:** mitigated.

#### 6.4.2 Split-view

- **Detection:** Witness cosignature (§15 MUST).
- **Residual:** A7 + A8.
- **Status:** mitigated for A7 alone.

#### 6.4.3 Backdated entries

- **Detection:** Consistency proofs from prior STHs to current STHs.
- **Residual:** Backdating within MMD.
- **Status:** mitigated beyond MMD.

#### 6.4.4 Retention violation

- **Detection:** Consistency proofs catch rewrite.
- **Status:** mitigated.

#### 6.4.5 Long-term log key compromise

- **Detection:** Witness quorum; rotation policy (§15 SHOULD).
- **Status:** mitigated-with-quorum.

### 6.5 Canonicalization attacks

#### 6.5.1 NFC ↔ NFD confusion

- **Detection:** §5.1 mandates NFC pre-canonicalization. Producers
  emit NFC; verifiers re-canonicalize from parsed objects, so an
  in-flight non-NFC variant either matches the producer's signed
  bytes (no harm) or breaks the signature.
- **Status:** mitigated.

#### 6.5.2 Number representation ambiguity

- **Detection:** Numbers inside hashed `context` MUST be encoded as
  strings (locked C-4 v0.2 tightening).
- **Status:** mitigated for hashed context.

#### 6.5.3 Duplicate keys

- **Detection:** RFC 8785 §3.2.4 rejects.
- **Status:** mitigated.

#### 6.5.4 BOM / leading whitespace

- **Detection:** JCS output is BOM-free; verifier canonicalizes from
  the parsed object.
- **Status:** mitigated.

#### 6.5.5 Type confusion

- **Detection:** Schema validation.
- **Status:** mitigated.

#### 6.5.6 Trailing data after JSON document

- **Detection:** Parse error.
- **Status:** mitigated.

### 6.6 Key management attacks

#### 6.6.1 Long-term issuer key compromise (A4)

- **Detection:** Trusted timestamps (§11) bound the pre-compromise
  window.
- **Status:** mitigated pre-compromise; everything after is suspect.

#### 6.6.2 Cross-role key reuse

- **Detection:** Verifiers SHOULD warn when two `*_key_id` values
  are equal.
- **Status:** mitigated by SPEC.md §9.1; deployment posture
  required.

#### 6.6.3 Shared / weak RNG

- **Status:** out of scope (CR-3 explicitly excludes).

### 6.7 Governance attacks

#### 6.7.1 Impact-tag namespace pollution

- **Detection:** Closed core registry; unknown tags are
  informational.
- **Status:** mitigated.

#### 6.7.2 Conformant-log registry capture

- **Status:** future work; not exploitable in v0.2.

#### 6.7.3 Witness collusion at scale

- **Status:** mitigated-with-quorum (≥2 independent witnesses
  recommended).

### 6.8 Upstream context attacks (the residual)

| ID | Attack | AERF behavior |
|---|---|---|
| 6.8.1 | Prompt injection at ingestion | Receipt records faithfully via `context_hash_sha256`. |
| 6.8.2 | Tool poisoning | Same. |
| 6.8.3 | Memory contamination | Same. |
| 6.8.4 | Retrieval poisoning | Same. |
| 6.8.5 | Common-mode failure | All signatures valid; documented residual. |

AERF records what was, not what should have been. Closing this
surface is a composition problem with in-toto/SLSA, C2PA, and
retrieval-attestation patterns.

### 6.9 Operational attacks

#### 6.9.1 DoS against the parent agent (forces async)

- **Detection:** Conforming verifiers fail closed.
- **Status:** mitigated by spec; deployment posture required.

#### 6.9.2 MMD-window evasion

- **Detection:** Monitor outage longer than MMD is itself an alert.
- **Status:** documented; mitigated by OP-3.

#### 6.9.3 Time-of-check time-of-use between PDP eval and action

- **Detection:** Same as split-context (6.3.3).
- **Status:** mitigated for honest hashes.

#### 6.9.4 Clock skew attacks

- **Detection:** RFC 3161 + log STH timestamp bracket `observed_at`.
- **Status:** mitigated in production profile.

---

## 7. STRIDE per entity (compressed)

| Entity | Spoof | Tamper | Repudiate | Info disclose | DoS | EoP |
|---|---|---|---|---|---|---|
| Issuer | Ed25519 sig (§7) | Ed25519 sig | Receipt + log inclusion | Out of scope | OP-fallback | n/a |
| Agent | `agent_signature` if present | Same | Receipt | `context` privacy (§4.5) | n/a | n/a |
| Parent | `parent_signature` (§4.6) | Same | Counter-sign on log | n/a | Forces sync→fail-closed | n/a |
| PDP | `pdp_signature` over tuple (§4.6) | Same | Verdict on log | Policy hash visibility | Forces sync→fail-closed | n/a |
| Log | STH sig + witness cosig | Consistency proof | Append-only | n/a (public) | Liveness, not safety | n/a |
| Witness | Witness cosig key | Same | n/a | n/a | Quorum design | n/a |
| Monitor | n/a | n/a | n/a | n/a | OP-3 | n/a |
| Verifier | n/a | n/a | n/a | Key acquisition (OP-1) | n/a | n/a |

---

## 8. Defense mapping

| Surface | Ed25519 sig | Chain hash | Parent sig | PDP sig | Log + witness | Timestamp | NFC + string-num |
|---|---|---|---|---|---|---|---|
| Receipt forgery (6.1) | §7, §10.1 | — | — | — | — | — | — |
| Receipt tamper (6.1.2) | §7 | — | — | — | — | — | — |
| Chain reorder/skip (6.2) | — | §8 | — | — | §15 | — | — |
| Genesis spoof (6.2.3) | — | C-6 (§8.1) | — | — | §15 | — | — |
| C-12 base (6.3.1) | — | — | §16 | §17 | §15 | — | — |
| Tag stripping (6.3.2) | — | — | upstream OP-5 | — | — | — | — |
| Split-context (6.3.3) | — | — | — | §17 | — | — | — |
| PDP bypass (6.3.5) | — | — | — | §3, §17 | — | — | — |
| Common-mode (6.3.6) | — | — | path-id (OP-4) | — | — | — | — |
| Log split-view (6.4.2) | — | — | — | — | §15 witness | — | — |
| Backdate (6.4.3) | — | — | — | — | §15 MMD | §11 | — |
| Canonicalization (6.5) | — | — | — | — | — | — | §5.1 |
| Issuer key compromise (6.6.1) | — | — | (degrades) | (degrades) | (degrades) | §11 | — |
| Cross-role key reuse (6.6.2) | — | — | — | — | — | — | §9.1 SHOULD |
| Tag pollution (6.7.1) | — | — | — | — | — | — | closed registry |
| Upstream context (6.8) | — | — | — | — | — | — | out of scope |
| Parent DoS (6.9.1) | — | — | fail-closed | — | — | — | — |

The blank cells matter. Each one says: this defense layer does not
help against this attack. The C-12 row carries three positive cells
across three different defense layers; that pattern is the
multi-mechanism property the v0.2 design buys.

---

## 9. Conformance levels and what they buy

| Profile | Defends against | Does not defend against |
|---|---|---|
| Base | Forgery, tamper, reorder, schema confusion. | Backdating, split-view, omission, key-compromise time bounds. |
| Production | + key-compromise time bounds, backdating beyond MMD, log omission, log split-view (with witness). | Quorum compromise; common-mode; tag stripping. |
| Production + multi-witness (≥2) | + single-witness compromise (A8). | Quorum >1; common-mode; tag stripping. |
| Production + multi-witness + independent PDP/parent paths | + common-mode evaluation collusion (A3 + A5 sharing one path). | Common-mode at the upstream context layer (A10). |

The progression is monotonic.

---

## 10. Residual risks

### 10.1 Common-mode failure on poisoned upstream context

The defining residual. AERF binds to what the agent saw; if the
upstream context is poisoned, every signer who re-evaluates against
the same context will, in good faith, sign an incorrect verdict.
The receipt is then internally consistent and externally untrue.

The right place to attack this is upstream: provenance for the
agent's input context. AERF is a downstream evidence layer.

v0.2 detection-only hooks:

- `parent_evaluation_path_id` lets parents declare path
  independence; monitors flag colliding path IDs.
- `context_hash_sha256` makes context distribution auditable.
- The transparency log preserves the historical record for upstream
  audits.

### 10.2 Tag stripping at the receipt layer

If `impact_tags` is determined by the agent's self-report, an
attacker controlling the agent can strip tags and bypass the sync
counter-sign requirement. v0.2 requires (OP-5) that tags be pinned
by the PEP before the issuer signs. PEP-side tag signing is future
work.

### 10.3 Quorum compromise

An adversary holding two or more keys from the {agent, issuer,
parent, PDP, log, witnesses} set defeats the receipt-layer defenses.
The transparency log makes resulting receipts permanent; detection
becomes forensic rather than preventive.

### 10.4 Pre-issuance trust

AERF assumes the issuer's signing key is honestly held at signing
time. The detection layer here is the trusted timestamp and the
multi-issuer co-signing pattern.

### 10.5 Verifier key acquisition (OP-1)

If a verifier acquires the wrong public key for any signer, the
entire defense graph collapses. Held C-10 explores JWK / DID
alternatives.

---

## 11. v0.1 → v0.2 delta

### 11.1 Closed in v0.2

| v0.1 gap | v0.2 closure |
|---|---|
| Compromised lower agent (A3) produces undetectable false claims (C-12 base) | `parent_signature` MUST for HIGH-IMPACT (§16); `pdp_signature` SHOULD/MUST with context binding (§17); transparency log (§15) |
| Split-context between PDP eval and action | `pdp_signature` binds `(context_hash, policy_hash, in_policy)` tuple |
| Loose JCS subset leaves canonicalization edges underspecified | Full RFC 8785 + NFC + string-encoded numbers in context (locked C-4) |
| No HIGH-IMPACT semantics | `impact_tags` field with closed core registry (locked C-21) |
| No transparency-log conformance criteria | §15 (locked C-22) |

### 11.2 Newly visible in v0.2

| New surface | Status |
|---|---|
| Tag stripping at receipt layer | Documented limit (§12.7) |
| Common-mode failure on poisoned context | Documented limit (§12.6) |
| Witness collusion | Mitigated-with-quorum |
| Cross-role key reuse | Mitigated by SHOULD; deployment posture |
| Conformant-log registry capture | Future work |

### 11.3 Unchanged

| Surface | Why |
|---|---|
| EVIDENCE-profile replay (no token semantics) | Locked C-16; AUTHZ profile (C-17) addresses |
| Single conformance level | Locked C-19 |
| Receipt ID format | Held C-15 |

---

## 12. Out of scope

- Compliance attestation.
- Authorization enforcement.
- Hardware key isolation.
- Network transport.
- Storage and retention.
- Privacy regimes.
- Upstream context provenance (§10.1).
- Hardware fault injection, side-channel attacks on signing devices.

---

## 13. Open questions

1. PEP-side tag signing to close 6.3.2.
2. Conformant-log registry governance.
3. Multi-witness quorum spec.
4. Context-provenance composition with in-toto/SLSA and retrieval
   attestation.
5. Receipt ID resolution (held C-15).
6. Independent-evaluation-path enforcement.

---

## 14. References

- RFC 2119 / 8174 — Key words.
- RFC 6962 / 9162 — Certificate Transparency.
- RFC 8032 — Ed25519.
- RFC 8785 — JSON Canonicalization Scheme.
- Sigstore / Rekor — Action-level transparency lineage.
- in-toto, SLSA — Build-provenance lineage.
- XACML — PDP / PEP separation.
- OWASP Agentic AI — Threats and Mitigations.
- AERF `SPEC.md`, `DECISIONS.md`.

---

## Appendix A. Attacker capability cheat sheet

```
A1  network attacker (Dolev-Yao)
A2  malicious verifier
A3  compromised lower agent  <-- the C-12 adversary
A4  compromised issuer
A5  compromised parent
A6  compromised PDP
A7  compromised log
A8  compromised witness
A9  compromised registry editor
A10 upstream context attacker  <-- the residual adversary
A11 quorum compromise (any 2+ of A3..A8)
```

C-12 closure: **no single capability A3..A8 alone can produce an
undetected false truth claim on a HIGH-IMPACT action.** Common-mode
(A10) is residual; quorum compromise (A11) degrades to detection-
only via the transparency log.

---

*End of THREAT-MODEL.md, AERF v0.2.0-draft.1.*
