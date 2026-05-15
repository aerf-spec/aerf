# AERF — Agent Evidence Receipt Format

> **Document status:** `v0.2.0-draft.1` — **Public Review Draft, May 2026.**
> Not yet stable. The wire format may change before v0.2.0. Do not
> cite as final.

> **Editor:** Aniketh Maddipati. **Reference producer:** `agentmint`
> 0.2.x (separate repository). **Reference verifier:**
> [`verifiers/go/`](./verifiers/go/) in this repository.

---

**Every section header below is normatively scoped to v0.2.0-draft.1
unless explicitly noted otherwise.** Open questions for v0.2.0 stable
are listed in §13.

v0.2.0-draft.1 closes held decision C-12 (compromised lower agent
issuing a false `in_policy=true` claim) with three layered defenses
introduced in §4.6, §15, §16, and §17. v0.1 receipts that omit the
new fields remain valid under v0.2 verifiers; see §3.

---

## 1. Introduction

### 1.1 Background and motivation

Modern AI systems are increasingly *agentic*: software agents take
multi-step actions on behalf of users, calling tools, mutating external
state, and reaching decisions that have legal, financial, or clinical
consequences. Existing logging and observability formats describe
*what a service did*; they do not constitute portable cryptographic
evidence that a particular agent took a particular action under a
particular policy at a particular time.

AERF — the **Agent Evidence Receipt Format** — is a wire format for
exactly that. An AERF receipt is a small Ed25519-signed JSON document
that records the action, the policy decision, the evidence, and the
observation time, and links to the policy that authorized it. A
receipt plus the issuer's public key is a complete, independently
verifiable audit artifact. No AERF software, account, or service is
required to verify one.

### 1.2 Design goals

1. **Portable, file-based audit trail.** A receipt is a single JSON
   file. Verifying it requires only a public key and a small static
   verifier.
2. **Standards-leaning crypto.** Ed25519 (RFC 8032), SHA-256 / SHA-512
   (FIPS 180-4), SPKI public keys (RFC 8410), RFC 3161 timestamps,
   RFC 9162 transparency logs.
3. **Algorithm agility without inventory creep.** Algorithms are
   declared per-field with a registry, but the v0.2 registry is
   deliberately minimal (Ed25519, SHA-256).
4. **Verifier minimalism.** The reference verifier is one Go module
   with only the language standard library on its critical path.
5. **Tamper evidence beyond a single receipt.** Receipts chain via a
   Merkle structure (linear chain as the degenerate case) and MAY be
   committed to an append-only transparency log (§15).
6. **Compliance-framework neutrality.** Receipts carry generic
   `compliance_tags` rather than hardcoded references to any one
   framework.
7. **Defense in depth across signers.** In multi-agent topologies a
   single compromised signing key MUST NOT be sufficient to produce
   an undetected false truth claim on a high-impact action (§4.6,
   §16, §17).

### 1.3 Out of scope

- **Authorization tokens.** AERF v0.2 specifies the EVIDENCE profile
  only. The AERF-AUTHZ profile (single-use tokens for action
  authorization) is acknowledged as future work (held decision C-17).
- **Transport, discovery, key distribution.** AERF specifies how
  receipts are signed and verified, not how they are exchanged.
- **Storage and retention policies.** Out of scope.
- **Privacy regimes.** AERF surfaces privacy considerations
  (§4.5) but does not legislate them.
- **Upstream context provenance.** AERF binds to the input context
  the agent observed via `context_hash_sha256` (§4.6) but does not
  attest the provenance of that context. See §12.6.

### 1.4 Relationship to existing standards

AERF deliberately does not invent new cryptography. Where possible it
reuses the building blocks of adjacent specifications:

- **W3C Verifiable Credentials.** AERF is narrower in scope (single
  domain: AI agent actions) and uses a simpler envelope. A receipt
  could in principle be wrapped as a JWS-secured VC.
- **C2PA (Content Provenance).** C2PA secures media provenance with
  embedded manifests; AERF secures *action* provenance with detached
  receipts. The signing primitives overlap; the data models do not.
- **JWS / JOSE (RFC 7515).** AERF receipts are not JWS today. The
  signature is a hex-encoded Ed25519 signature on a canonical JSON
  payload. RFC 7515 is referenced for the lineage of counter-signature
  semantics adopted in §16; AERF does not use JWS counter-signatures.
- **Certificate Transparency (RFC 6962, RFC 9162).** AERF's
  transparency log integration (§15) consumes the existing
  append-only, Merkle-proof, witnessed-STH pattern; AERF does not
  re-specify CT.
- **Sigstore / Rekor.** AERF borrows the *posture* of the Sigstore
  ecosystem — single-binary verifier, transparent crypto, prefer
  verifiability over performance — but AERF is concerned with
  agent actions rather than artifacts or build provenance.
- **XACML.** The PDP / PEP separation referenced in §4.6 and §17 is
  from XACML.

## 2. Terminology

The key words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and
**MAY** in this document are to be interpreted as described in BCP 14
(RFC 2119, RFC 8174) when, and only when, they appear in all
capitals.

- **Agent.** A software actor that executes actions on behalf of a
  principal (user, organization, or another agent).
- **Tool.** An external capability the agent calls (an API, a
  database, a model invocation, etc.).
- **Plan.** A signed envelope that defines the scope of allowed
  actions for an agent or set of agents over a bounded period.
- **Plan receipt.** A signed JSON document representing a plan.
- **Evidence receipt.** A signed JSON document representing a single
  observed action, this specification's main subject.
- **Receipt.** When unqualified, refers to an evidence receipt.
- **Issuer.** The party whose key signs receipts. Typically the
  notary infrastructure of the agent's deployment.
- **Verifier.** Any party who checks a receipt's signature, chain,
  timestamp, and (where present) multi-agent and transparency-log
  fields.
- **Parent agent.** A higher agent in a multi-agent topology that
  counter-signs receipts originating from a child (§16).
- **PDP (Policy Decision Point).** An independently-keyed evaluator
  that signs the verdict tuple defined in §4.6.
- **PEP (Policy Enforcement Point).** The component that gates the
  action based on the PDP verdict. The PEP does not sign in v0.2.
- **Transparency log.** An append-only, witnessed Merkle log to which
  receipts (or their leaf hashes) are submitted. See §15.
- **Witness.** A third party that co-signs a log's Signed Tree Head
  to defend against split-view attacks.
- **MMD (Maximum Merge Delay).** The upper bound on the delay between
  log submission and inclusion in a signed tree head (§15, §16).
- **Genesis receipt.** The first receipt of a given plan's chain.
  See §8.1.
- **Conformant.** Compliant with all **MUST** requirements of this
  specification at the conformance level defined in §3.
- **HIGH-IMPACT.** An action whose receipt carries one or more
  `impact_tags` (§4.6, §17). HIGH-IMPACT actions trigger the strict
  multi-signer rules in §3 and §16.

## 3. Conformance

A single conformance level applies (locked decision C-19): an
implementation is either **conformant** or **non-conformant**. The
specification does not distinguish issuer-, verifier-, or
auditor-level conformance.

A **conformant verifier** MUST, given a receipt and the relevant
public keys:

1. Parse the receipt according to §4.
2. Validate the canonical JSON encoding per §5.
3. Verify the Ed25519 signature per §7 and §10.
4. If `previous_receipt_hash` is present, perform the chain check
   defined in §8 against any provided predecessor receipts.
5. If the receipt's `impact_tags` field is present and non-empty:
   1. The receipt MUST include `parent_signature`, `parent_key_id`,
      `pdp_signature`, `pdp_key_id`, and `context_hash_sha256`.
      Absence of any of these is a verification failure.
   2. If a parent public key is available, verify `parent_signature`
      per §10.1 step 6 and §16.
   3. If a PDP public key is available, verify `pdp_signature`
      against the canonical PDP-bound tuple per §10.1 step 7 and §17.
6. If the action delegates to a child agent (a non-receipt-layer
   signal observable to the verifier) and `impact_tags` is empty,
   `parent_signature` MUST be present within MMD of `observed_at`.
   Absence after MMD is a verification failure (§16).
7. If `log_inclusion_proof` is present and a log public key is
   available, verify the proof per §10.1 step 8 and §15.
8. If the implementation targets the **production profile**, verify
   the RFC 3161 timestamp per §11 and require a valid
   `log_inclusion_proof` per §15.

The reference verifier shipped with v0.2.0-draft.1 enforces steps 1–7
when the relevant public keys are supplied on the command line, and
falls back to v0.1 behavior (steps 1–3) when the new fields are absent
and no v0.2 keys are supplied. Step 8 (production profile) is
described normatively but is **optional in the reference verifier
for this draft.** This relaxation does **not** extend to other
implementations claiming production-profile conformance.

A **conformant producer** MUST, when issuing a receipt:

1. Populate all fields marked REQUIRED in §4.2.
2. Apply the canonicalization in §5.1 prior to signing.
3. Compute the Ed25519 signature exactly as in §7.
4. Omit `previous_receipt_hash` on a genesis receipt (§8.1; locked
   decision C-6); otherwise populate it according to §8.4.
5. When `impact_tags` is non-empty, populate `parent_signature`,
   `parent_key_id`, `pdp_signature`, `pdp_key_id`, and
   `context_hash_sha256` per §4.6.
6. When the action delegates to a child agent and `impact_tags` is
   empty, ensure `parent_signature` and `parent_key_id` are populated
   no later than MMD after the receipt is committed to the
   transparency log (§16).

A v0.1 receipt that does not carry any v0.2 fields remains a
conformant v0.2 receipt for non-HIGH-IMPACT actions: the v0.2 schema
adds fields and conditional requirements but does not retract any
v0.1 field.

## 4. Receipt data model

This specification defines the **AERF-EVIDENCE** profile. The
`type` field MUST be the string `notarised_evidence` for receipts
covered by this profile.

### 4.1 Top-level object

The full canonical example used throughout this document:

```json
{
  "id": "7473e179-001c-4d3b-94bc-d0f53dd6eec6",
  "type": "notarised_evidence",
  "plan_id": "bc023208-ea24-410a-a280-ff36820e18a6",
  "agent": "claims-agent",
  "action": "submit:claim:CLM-9920",
  "in_policy": true,
  "policy_reason": "matched scope submit:claim:*",
  "evidence_hash_sha512": "b35d8ba27ad113c45d80d29c82c9f3c79308cd94ccf351623a074ed8a32c1d1325026b692f412d6e5907c78ad3afcb8edb44b492b24b499c453953ddbb39e30c",
  "evidence": {
    "tool": "submit-claim",
    "claim_id": "CLM-9920",
    "amount": 1250.00,
    "patient_id_hash": "sha256:5f4dcc3b5aa765d61d8327deb882cf99aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "diagnosis_code": "ICD10:E11.9",
    "service_date": "2026-04-30",
    "provider_npi": "1234567890"
  },
  "observed_at": "2026-05-06T16:22:33.490443+00:00",
  "compliance_tags": ["aiuc:E015", "aiuc:D003", "aiuc:B001"],
  "key_id": "c348d3c785c92249",
  "policy_hash": "260eca8ac43ae65e804c7107441acf45500d7f59a275c372d03a9a29985d6bf1",
  "session_id": "8d07720e-337e-4b4c-b92b-b3eccbc8c2e9",
  "session_trajectory": [
    {
      "action": "submit:claim:CLM-9920",
      "agent": "claims-agent",
      "in_policy": true,
      "observed_at": "2026-05-06T16:22:33.490443+00:00"
    }
  ],
  "plan_signature": "3e5b83e83b77bfa233c3517b4ffd55a00bf8d674c3d4cb578bb2b559849310058baa103083c3a89bf02efe0abf5fa7ba15c90132d6c7a04be359f868dea8ee01",
  "signature": "8bd989a95ab6086379bb67b617cce983e9bbe3a580d7d458358342df6bbb0971cb46b59873879b99bb6ab9c97e8631a81926bed8ab8e5f891359176804e97208"
}
```

This is the genesis receipt of a chain — `previous_receipt_hash` is
omitted (§8.1). The same file is shipped as
[`verifiers/go/example/receipt.json`](./verifiers/go/example/receipt.json)
and is preserved verbatim across v0.1 and v0.2 to lock regression
behavior.

### 4.2 Required fields

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Receipt identifier. v0.2: UUIDv4 (held decision C-15). |
| `type` | string | Profile discriminator. v0.2: `"notarised_evidence"`. |
| `plan_id` | string | Identifier of the plan receipt this evidence references. |
| `agent` | string (≤256) | Asserted identity of the acting agent. |
| `action` | string (≤128) | Action being notarised. Charset `[A-Za-z0-9_:.-]`. |
| `in_policy` | boolean | Whether the action satisfied the plan's policy at observation time. |
| `policy_reason` | string | Human-readable explanation. |
| `evidence_hash_<alg>` | string | Digest of the canonical JSON of `evidence`. The `<alg>` suffix declares the algorithm (locked decision C-3). v0.2: `evidence_hash_sha512`. |
| `evidence` | object | Inline evidence payload (held decision C-8 — see §4.5). |
| `observed_at` | string | ISO 8601 timestamp of observation. Self-reported in base profile; production profile MUST anchor with RFC 3161 (§11). |
| `key_id` | string | Issuer's key identifier. v0.2: first 16 hex chars of SHA-256(public key) (held decision C-9). |
| `signature` | string | Hex-encoded Ed25519 signature per §7. |

### 4.3 Optional fields

| Field | Type | Description |
|-------|------|-------------|
| `previous_receipt_hash` | string | SHA-256 hex digest of the canonical PAYLOAD of the previous receipt in the same plan's chain (locked decisions C-2, C-7, C-24). MUST be omitted on the genesis receipt (locked decision C-6). |
| `plan_signature` | string | Copy of the referenced plan receipt's signature, for direct receipt→plan binding. |
| `agent_signature` | string | Optional second signature by the acting agent's own key. Distinct from `parent_signature` (§4.6). |
| `agent_key_id` | string | Key ID of the agent's signing key, when `agent_signature` is present. |
| `policy_hash` | string | SHA-256 hex of canonical `{scope, checkpoints, delegates_to}` of the plan. REQUIRED when `pdp_signature` is present. |
| `output_hash` | string | SHA-256 hex of canonical action output, when supplied. |
| `session_id` | string | Issuer-scoped session identifier. |
| `session_trajectory` | array | Recent action trace within the session. |
| `session_escalation` | string\|null | Escalation marker emitted by the session policy. |
| `reasoning_hash` | string | SHA-256 hex of the agent's reasoning text, when captured. |
| `compliance_tags` | array | Generic compliance tags (locked decision C-14). |
| `aiuc_controls` | array | **Deprecated** (locked decision C-14); will be removed by v1.0. |
| `timestamp` | object | RFC 3161 timestamp token information. REQUIRED for the production profile (locked decision C-11). |

### 4.4 Field constraints

- `id` and `plan_id` MUST be valid UUIDv4 strings in v0.2.
- `agent` MUST NOT contain control characters (`< 0x20`).
- `action` MUST match `^[A-Za-z0-9_:.\-]+$` and be ≤128 characters.
- `evidence` MUST be JSON-serializable. Implementations SHOULD reject
  serialized `evidence` larger than 1 MiB.
- All hex-encoded fields MUST be lowercase.
- Timestamps MUST be ISO 8601 with timezone offset.

### 4.5 Privacy considerations

The current reference producer inlines the full `evidence` object
(held decision C-8). This is appropriate for low-sensitivity tool
calls but not for receipts that pass through hands less trusted than
the original issuer. Until C-8 resolves, deployments handling
sensitive payloads SHOULD:

- Hash sensitive identifiers before inclusion (the canonical example
  hashes `patient_id` to `patient_id_hash`).
- Strip free-text fields that may contain PII.
- Treat the inlined `evidence` as in-band-confidential; the
  `evidence_hash_<alg>` field allows separating the digest from the
  payload in a future profile.

A non-inlining variant of the EVIDENCE profile is an open candidate
for v0.3.

### 4.6 Multi-agent verification fields

This section is new in v0.2.0-draft.1 and is the receipt-layer
closure of decision C-12. Each field below is OPTIONAL in isolation;
the conditional requirements in §3 determine when a conformant
producer MUST populate it.

| Field | Type | Description |
|-------|------|-------------|
| `parent_signature` | string | Hex-encoded Ed25519 signature by the parent agent's key over the canonical receipt payload (computed with `parent_signature`, `parent_key_id`, `signature`, `timestamp`, and `log_inclusion_proof` removed). REQUIRED when `impact_tags` is non-empty; REQUIRED within MMD when the action delegates to a child agent and `impact_tags` is empty; otherwise OPTIONAL. See §16. |
| `parent_key_id` | string | First 16 lowercase hex chars of SHA-256(parent public key). REQUIRED when `parent_signature` is present. |
| `parent_evaluation_path_id` | string | OPTIONAL declaration that the parent's evaluation path is independent of the child's. UTF-8 string ≤128 characters. Used by monitors to detect common-mode collusion (§12.6). |
| `pdp_signature` | string | Hex-encoded Ed25519 signature by the Policy Decision Point over the canonical JSON (per §5.1) of the tuple `{"context_hash_sha256", "in_policy", "policy_hash"}`. REQUIRED when `impact_tags` is non-empty; SHOULD be present otherwise. See §17. |
| `pdp_key_id` | string | First 16 lowercase hex chars of SHA-256(PDP public key). REQUIRED when `pdp_signature` is present. |
| `context_hash_sha256` | string | SHA-256 hex digest of the canonical JSON (per §5.1, with the §5.1 numeric-as-string rule applied) of the input context the agent observed. REQUIRED when `pdp_signature` is present; OPTIONAL otherwise. |
| `log_inclusion_proof` | object | RFC 9162-aligned audit-path inclusion proof against a conformant transparency log (§15). MUST be present on a receipt that has been committed to a log. The field is added after issuance and is excluded from the issuer signature input (§7) and from `previous_receipt_hash` input (§8.4). |
| `impact_tags` | array of string | Zero or more tags drawn from the closed core registry (§17) or the `x-{vendor}-` namespace. Distinct from `compliance_tags`. The presence of one or more tags marks the receipt as HIGH-IMPACT and triggers the requirements in §3. |

The shape of `log_inclusion_proof`:

```json
{
  "log_id": "string identifier of the conformant log",
  "leaf_hash": "hex sha256 of the leaf",
  "tree_size": 12345,
  "audit_path": ["hex sha256", "..."],
  "sth": {
    "tree_size": 12345,
    "root_hash": "hex sha256",
    "timestamp": "RFC3339 timestamp, Z"
  },
  "sth_signature": "hex ed25519 signature over the canonical JSON of sth"
}
```

The PDP-bound tuple is signed *before* issuance and is part of the
issuer-signed payload. The transparency-log inclusion proof is added
*after* issuance and is not signed by the issuer. The parent
counter-signature is computed against the issuer-signed payload and
is therefore a strict ratchet on top of the issuer signature: a
verifier presented with `parent_signature` but no issuer signature,
or with `parent_signature` over different content than the issuer
signed, MUST reject.

## 5. Serialization

### 5.1 Canonical JSON

v0.2 resolves held decision C-4. The canonicalization used for
signing, for chaining, for `context_hash_sha256`, and for the
PDP-bound tuple is **full RFC 8785 (JCS)**, with two normative
tightenings on top of JCS:

1. All string values MUST be Unicode-normalized to NFC (Unicode
   Standard Annex #15) before JCS encoding. A producer that emits a
   non-NFC string is non-conformant; a verifier MAY reject any
   string that is not already in NFC.
2. Inside any object whose canonical bytes are fed into
   `context_hash_sha256`, numeric values MUST be encoded as JSON
   strings rather than JSON numbers. This sidesteps the residual
   number-representation ambiguity that JCS does not fully eliminate
   for application-level equality of contexts.

The v0.1 reference producer used a strict subset of JCS:

```python
json.dumps(d, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
```

For the field set v0.1 producers actually emit (no nested context
fields, no numeric ambiguity inside hashed scopes), that subset is
contained in JCS. v0.1 receipts therefore continue to verify under
v0.2 verifiers without change, and the v0.1 example receipt is
preserved as a v0.2 regression vector.

The reference Go verifier in this repository implements JCS in
[`verifiers/go/canonicalize.go`](./verifiers/go/canonicalize.go) and
the v0.1-compatible path in
[`verifiers/go/verify.go`](./verifiers/go/verify.go).

## 6. Cryptographic primitives

### 6.1 Algorithm registry — signing (locked decision C-1)

| Tag | Algorithm | Status in v0.2 |
|-----|-----------|----------------|
| `ed25519` | RFC 8032 Ed25519 | **Required.** Only signing algorithm in v0.2. |

Conformant producers MUST sign with Ed25519 in v0.2. Conformant
verifiers MUST support Ed25519 in v0.2. This applies to the issuer
signature, the parent counter-signature, the PDP signature, and the
log STH signature.

### 6.2 Algorithm registry — hashing (locked decision C-2)

| Tag | Algorithm | Status in v0.2 |
|-----|-----------|----------------|
| `sha256` | FIPS 180-4 SHA-256 | **Required** for `previous_receipt_hash`, `context_hash_sha256`, and `log_inclusion_proof` leaves. |
| `sha512` | FIPS 180-4 SHA-512 | **Permitted** for internal field digests under C-3. |

The chain-hash algorithm is fixed at SHA-256 in v0.2 (locked decision
C-2). Internal hashes (e.g. `evidence_hash_sha512`, `policy_hash`,
`output_hash`, `reasoning_hash`) declare their algorithm per locked
decision C-3, currently via field-name suffix.

### 6.3 Algorithm registry — context hashing

`context_hash_sha256` is computed with SHA-256 only in v0.2. The
algorithm is declared via the field-name suffix per C-3. Future
versions MAY add `context_hash_sha512` or other algorithms; v0.2
verifiers MUST reject contexts hashed under unrecognized suffixes.

## 7. Signing procedure

A conformant producer signs an evidence receipt by:

1. Constructing the receipt object as in §4 with placeholder empty
   strings for `signature` and (if applicable) `timestamp` fields.
   If the receipt will carry v0.2 multi-agent fields, the
   `pdp_signature`, `pdp_key_id`, `context_hash_sha256`, and
   `impact_tags` fields MUST already be populated at this point.
2. Removing the `signature`, `timestamp`, `parent_signature`,
   `parent_key_id`, and `log_inclusion_proof` fields from the
   payload.
3. Canonicalizing the remaining object per §5.1.
4. Computing `signature = Ed25519_Sign(issuer_private_key,
   canonical_payload)`.
5. Hex-encoding the resulting 64 bytes (lowercase) and assigning it
   to the `signature` field.
6. Optionally requesting an RFC 3161 timestamp on the *signed*
   payload (canonical bytes ∥ signature) and attaching the resulting
   token info to the `timestamp` field.

`parent_signature` and `log_inclusion_proof` are added after step 5
and are not part of the issuer-signed canonical payload. This is
deliberate: the parent counter-signature is a ratchet on top of the
issuer signature (§16), and the log inclusion proof necessarily
post-dates issuance (§15).

The reference producer in `agentmint` 0.2.x implements this in
`agentmint.notary.Notary.notarise()` (separate repository).

## 8. Hash chaining (locked decision C-5)

Receipts within a single plan form a **Merkle structure**. A linear
chain (one new receipt per slot) is the degenerate single-leaf-per-
level case. The reference verifier in v0.2.0-draft.1 verifies signatures,
the multi-agent fields, and (optionally) chain links and log proofs;
the following rules are normative for producers and for conformant
chain-aware verifiers.

### 8.1 Genesis (locked decision C-6)

The first receipt of a chain MUST omit the `previous_receipt_hash`
field entirely. Verifiers MUST treat absence of the field as the
genesis signal. **Presence of the field with `null`, an empty string,
or any zero value is a conformance error.**

### 8.2 Linear chain (degenerate case)

For a receipt at chain position *n > 0*, `previous_receipt_hash` is
defined per §8.4 against the receipt at position *n-1*.

### 8.3 Merkle structure

For a chain of length *N > 1*, an issuer MAY publish a Merkle root
summarising the entire chain. The Merkle root is computed by:

1. Forming the leaf set as the SHA-256 of each receipt's canonical
   payload (§8.4).
2. Pairing leaves left-to-right, hashing each pair under SHA-256, and
   continuing until a single 32-byte root remains.
3. If a level has an odd number of nodes, the last node is duplicated.

A future draft will normatively specify a Merkle proof format for
inter-chain summaries. In v0.2.0-draft.1 the Merkle root is
informational; per-receipt proofs go through `log_inclusion_proof`
(§15).

### 8.4 Chain hash input (locked decisions C-7, C-24)

`previous_receipt_hash` is the SHA-256 hex digest of the canonical
**payload** of the previous receipt, computed by:

1. Taking the previous receipt object.
2. Removing the following fields:
   - `signature` (locked C-7)
   - `timestamp` (locked C-7)
   - `parent_signature` (locked C-24, added in v0.2)
   - `parent_key_id` (locked C-24, added in v0.2)
   - `log_inclusion_proof` (locked C-24, added in v0.2)
3. Canonicalizing the remainder per §5.1.
4. Hashing the canonical bytes with SHA-256 and hex-encoding.

The fields excluded from the chain-hash input share the property that
they are added to the receipt **after issuance**. Including them in
`previous_receipt_hash` would prevent a chain from being verified
before its parent counter-signature and log proof arrive, defeating
the §15 / §16 ratchet model. Fields decided pre-issuance and
claim-bearing — `pdp_signature`, `pdp_key_id`, `context_hash_sha256`,
`impact_tags` — are included in the chain-hash input.

## 9. Key management

### 9.1 Key ID format (held decision C-9)

The current reference producer derives `key_id`, `parent_key_id`, and
`pdp_key_id` as the first 16 lowercase hex characters of
`SHA-256(public_key_bytes)`. This is a held decision; alternatives
under consideration include the JWK thumbprint of RFC 7638.

Conformant verifiers SHOULD warn when two distinct role keys
(`key_id`, `parent_key_id`, `pdp_key_id`) resolve to the same value;
shared keys across roles void the independence assumption that the
multi-signer defenses in §16 and §17 depend on.

### 9.2 Public-key transport (held decision C-10)

The reference public-key encoding is SPKI PEM (RFC 8410). The DER
form is the 12-byte Ed25519 SPKI prefix
`30 2a 30 05 06 03 2b 65 70 03 21 00` followed by the 32-byte raw
public key. Verifiers MUST accept this form. Future drafts may
additionally specify JWK or DID transport.

## 10. Verification procedure

### 10.1 Steps

A conformant verifier, given a receipt *R*, an issuer public key
*PK*, and optionally a parent public key *PK_parent*, a PDP public
key *PK_pdp*, and a log public key *PK_log*:

1. **Parse.** Decode *R* as a JSON object. Reject if invalid JSON.
2. **Schema.** Optionally validate against
   [`schemas/aerf-v0.2.json`](./schemas/aerf-v0.2.json) (or the v0.1
   schema for v0.1-shaped receipts).
3. **Signature extraction.** Read the hex-encoded `signature` field
   and decode to 64 bytes. Reject if missing, wrong length, or
   invalid hex.
4. **Canonicalize.** Remove `signature`, `timestamp`,
   `parent_signature`, `parent_key_id`, and `log_inclusion_proof`
   fields. Canonicalize the remainder per §5.1.
5. **Verify issuer signature.** Compute `Ed25519_Verify(PK,
   canonical, sig)`. On failure, reject the receipt as non-authentic.
6. **Verify parent counter-signature.** If `parent_signature` is
   present and *PK_parent* is supplied: re-canonicalize the payload
   per step 4 and verify
   `Ed25519_Verify(PK_parent, canonical, parent_sig)`. If
   `impact_tags` is non-empty and `parent_signature` is missing,
   reject. If *PK_parent* was not supplied, emit a warning and
   continue unless `--require-parent-sig` was set, in which case
   reject.
7. **Verify PDP signature.** If `pdp_signature` is present and
   *PK_pdp* is supplied: form the canonical JSON of the tuple
   `{"context_hash_sha256": <value>, "in_policy": <value>,
   "policy_hash": <value>}` per §5.1, then verify
   `Ed25519_Verify(PK_pdp, tuple_canonical, pdp_sig)`. The
   `context_hash_sha256` and `policy_hash` inside the tuple MUST
   byte-match the same fields at the top level of the receipt. If
   `impact_tags` is non-empty and `pdp_signature` is missing, reject.
   If *PK_pdp* was not supplied, emit a warning and continue unless
   `--require-pdp-sig` was set.
8. **Verify log inclusion proof.** If `log_inclusion_proof` is
   present and *PK_log* is supplied: verify the STH signature with
   *PK_log*, compute the leaf hash from the receipt's canonical
   payload (per §15), and check the audit path reaches the STH
   `root_hash`. If *PK_log* was not supplied, emit a warning and
   continue unless `--require-log` was set.
9. **Chain.** If `previous_receipt_hash` is present and a predecessor
   receipt is supplied, compute the chain-hash input per §8.4 of the
   predecessor and compare.
10. **Timestamp.** If `timestamp` is present, perform RFC 3161
    verification per §11.

### 10.2 Error codes

The reference verifier exits with:

| Code | Meaning |
|------|---------|
| `0`  | All applicable checks passed. |
| `1`  | A check failed (signature, parent signature, PDP signature, log inclusion, chain, timestamp). |
| `2`  | Usage / I/O error (file missing, bad PEM, etc.). |

Diagnostic output on stderr identifies which check failed and, where
applicable, which field or signer was responsible. The diagnostic
format is intentionally machine-parseable: a single line beginning
with `FAIL` followed by a short reason code.

## 11. Timestamp anchoring (locked decision C-11)

The **production profile** REQUIRES RFC 3161 trusted timestamps over
the signed payload. The **base profile** MAY rely on the producer's
self-reported `observed_at` only.

Trusted timestamps anchor a receipt to wall-clock time independently
of the issuer. Without them, a malicious issuer with retained access
to the signing key can backdate receipts. The reference producer
defaults to FreeTSA but accepts any RFC 3161-compatible TSA.

A conformant timestamp verification:

1. Re-canonicalizes the receipt *with* its signature attached
   (the bytes the TSA actually saw).
2. Confirms that the timestamped digest matches.
3. Validates the TSR signature chain to a trusted CA.

The reference Go verifier in v0.2.0-draft.1 does not yet implement
RFC 3161 verification; an OpenSSL-backed verifier ships in the
`agentmint` evidence ZIP for the time being.

## 12. Security considerations

### 12.1 Threat model

AERF v0.2 assumes:

- The issuer's signing key is honestly held at the moment of signing.
- The verifier reliably obtains the correct public key for each
  signer in scope (issuer, parent, PDP, log).
- An adversary may modify, replay, or reorder receipts in transit or
  at rest.
- An adversary may compromise one of the role keys (agent, issuer,
  parent, PDP, log, witness). The spec is designed so that no single
  compromise produces an undetected false truth claim on a
  HIGH-IMPACT action.

For a structured account of adversary capabilities, defense mapping,
and residual risks, see [`THREAT-MODEL.md`](./THREAT-MODEL.md).

C-7's payload-only chain-hash input (extended by C-24) has a
deliberate consequence: an adversary who obtains an issuer's signing
key can re-sign existing payloads without breaking chain integrity.
This is acceptable because key compromise breaks the signature trust
assumption regardless; chain-integrity decoupling buys the ability to
reason about ordering before asking about authenticity.

### 12.2 Replay (locked decision C-16)

The EVIDENCE profile has no replay concept — a receipt is a record,
not a token. A future AERF-AUTHZ profile (held decision C-17) will
specify single-use semantics.

### 12.3 Key compromise

Compromise of the issuer's private key renders all receipts signed
with that key indistinguishable from forgeries dated up to the
compromise window. Trusted timestamps (§11) are the recommended
mitigation: a trusted timestamp issued before the compromise window
attests that the receipt existed in its present form before that
moment. For HIGH-IMPACT receipts, the parent counter-signature and
the transparency-log entry survive issuer-key compromise as
independent evidence of pre-compromise content.

### 12.4 Malicious issuers

A malicious issuer can sign incorrect statements about an action.
AERF makes no claim about the truth of `evidence`; it only binds the
*statement* to the issuer. v0.2's multi-signer defenses (§16, §17)
force a malicious issuer to collude with the parent agent and the
PDP to produce a HIGH-IMPACT receipt that survives verification.

### 12.5 Compromised lower agent (resolution of C-12)

**The attack.** In a hierarchical multi-agent topology, a lower
agent's signing key may be compromised while the surrounding key
material is not. With v0.1's single-signer model, the compromised
agent can sign a receipt asserting `in_policy=true` for an action
that is actually out of policy. The issuer infrastructure, trusting
the agent's own attestation, propagates the false claim. Downstream
verifiers cannot distinguish this receipt from a legitimate one:
signatures attest authorship, not truth.

**The defense, three layers.**

1. **Counter-signature (§16).** For HIGH-IMPACT receipts, a parent
   agent with an independent signing key co-signs the receipt
   payload. A compromised child alone cannot produce a verifiable
   HIGH-IMPACT receipt; the attacker must additionally compromise
   the parent's key.
2. **PDP signature bound to context (§17).** An independently-keyed
   Policy Decision Point signs the tuple
   `(context_hash_sha256, policy_hash, in_policy)`. The verifier
   re-canonicalizes that tuple from the receipt's own fields and
   verifies. A compromised child cannot fabricate a verdict for a
   context it did not present to the PDP, and cannot swap a clean
   PDP verdict onto an altered context: both `context_hash_sha256`
   and `policy_hash` are bound into the PDP-signed tuple.
3. **Transparency log inclusion (§15).** The receipt is committed
   to an append-only, witnessed log. A false receipt becomes
   permanently visible to monitors. Detection post-hoc is forensic
   rather than preventive, but the receipt cannot be retracted.

The three layers constrain different adversary capabilities (parent
key, PDP key, log key). An adversary compromising any single key
fails to produce an undetected false claim. The C-12 attack now
requires extending compromise across at least two administrative
domains, which is precisely the property the multi-mechanism design
buys.

### 12.6 Common-mode failure

The §12.5 defenses assume the parent and the PDP arrive at their
verdicts via independent evaluation. If the parent agent
re-evaluates against the same poisoned upstream context the child
saw, it will, in good faith, reach the same wrong conclusion and
sign honestly. The signature is cryptographically valid; the truth
claim is wrong because the input was wrong upstream of the receipt.

AERF v0.2 cannot close this gap at the receipt layer. The right
place to address it is upstream provenance for the agent's input
context — the in-toto / SLSA family for build inputs, content
provenance (C2PA) for media inputs, and emerging
context-attestation patterns for retrieval and tool outputs. AERF is
the action-layer endpoint of those chains; it records what was, not
what should have been.

v0.2 exposes one detection-only hook: `parent_evaluation_path_id`
lets the parent declare that its evaluation path is independent of
the child's. Monitors can flag receipts where the path IDs are
identical, missing, or suspicious. This is a hook, not a defense.
This residual is documented and out of scope for v0.2.

### 12.7 Tag stripping

If `impact_tags` is determined by the agent's self-report, an
attacker controlling the agent can omit tags and bypass the sync
counter-sign requirement at the receipt layer. The verifier sees a
receipt that does not look HIGH-IMPACT and does not insist on
`parent_signature` or `pdp_signature`.

AERF v0.2 cannot close this gap at the receipt layer. The defense is
upstream: the Policy Enforcement Point MUST pin the tag set before
the issuer signs. A future profile may specify a separate PEP-side
signature over the tag set; v0.2 documents this as a known limit.

## 13. Open questions for v0.2 stable

The following are explicitly held open and will resolve before v0.2.0
stable or move to v0.3. See [DECISIONS.md](./DECISIONS.md) for the
full table.

- **C-8** Evidence inlining. Required, recommended, or prohibited for
  sensitive fields?
- **C-9** Key ID format. Stay with 16-hex-char SHA-256 prefix or
  switch to RFC 7638 JWK thumbprint?
- **C-10** Public-key transport. PEM only, or PEM ∪ JWK ∪ DID?
- **C-15** Receipt ID. UUIDv4, UUIDv7, or content-addressed?
- **C-17** Profile structure. When to specify AERF-AUTHZ?
- **C-18** Versioning policy. Adopt a formal wire-format versioning
  scheme distinct from implementation semver?
- **C-21 governance escalation.** v0.2 closes the impact-tag core
  registry. A working group process to extend it (and to curate the
  conformant-log registry referenced in §15) is future work.

## 14. References

- RFC 2119 / RFC 8174 — Key words for use in RFCs.
- RFC 3161 — Internet X.509 PKI Time-Stamp Protocol (TSP).
- RFC 6962 — Certificate Transparency.
- RFC 7515 — JSON Web Signature (referenced for counter-signature
  lineage; AERF does not use JWS).
- RFC 7517 — JSON Web Key (JWK).
- RFC 7638 — JWK Thumbprint.
- RFC 8032 — Edwards-Curve Digital Signature Algorithm (Ed25519).
- RFC 8410 — Algorithm Identifiers for Ed25519, Ed448, X25519, X448.
- RFC 8785 — JSON Canonicalization Scheme (JCS).
- RFC 9162 — Certificate Transparency Version 2.0.
- Unicode Standard Annex #15 — Unicode Normalization Forms.
- W3C — Verifiable Credentials Data Model 2.0.
- C2PA — Content Provenance and Authenticity, v1.x.
- Sigstore / Rekor — Action-level transparency lineage.
- XACML — PDP / PEP separation lineage.
- OWASP Agentic AI — Threats and Mitigations.
- AIUC-1 — AI Usage Controls.
- `agentmint-python` — reference producer.
  https://github.com/aniketh-maddipati/agentmint-python

## 15. Transparency log integration

A conformant AERF transparency log is an append-only Merkle log that
exposes receipt inclusion proofs to verifiers. AERF v0.2 does not
re-specify the log primitive; it consumes the RFC 6962 / RFC 9162
pattern.

A conformant log **MUST**:

1. Be append-only, with a Signed Tree Head (STH) emitted at a fixed
   cadence and signed by the log's key.
2. Support witness cosignature of STHs. A conformant log accepts
   third-party witness cosignatures and surfaces them alongside the
   STH.
3. Declare a Maximum Merge Delay (MMD): the upper bound, in seconds,
   between log submission and inclusion in a signed STH.
4. Provide RFC 6962 §2.1.2 Merkle audit-path proofs (consistency
   proofs and inclusion proofs).
5. Expose a public read API that any verifier can query without
   credentials.

A conformant log **SHOULD**:

1. Gossip STHs out-of-band to monitors and witnesses so that
   split-view attacks are detectable across the witness set.
2. Publish a key rotation policy describing how the log's
   STH-signing key is rotated and how a rotation is announced.

The receipt-side handle is `log_inclusion_proof` (§4.6). A verifier
that holds the log's STH-signing public key can:

- Verify the STH signature, anchoring the tree state.
- Compute the leaf hash from the receipt's canonical payload (using
  the §8.4 strip rules so the leaf is independent of post-issuance
  fields).
- Walk the audit path to confirm the leaf is in the tree under the
  STH's `root_hash`.

A monitor watching the log over time additionally verifies
consistency proofs from prior STHs to current STHs to detect
rewriting.

The list of accepted logs is a deployment choice in v0.2. A
curated conformant-log registry is future work and tracked under
C-21.

## 16. Counter-signature semantics

A counter-signature is a second Ed25519 signature, by a parent agent
in a multi-agent topology, over the issuer-signed payload. It exists
to make a single compromised child key insufficient for a false
HIGH-IMPACT truth claim.

### 16.1 Sync vs async

AERF v0.2 admits two arrival modes for `parent_signature`:

- **Sync counter-sign.** When `impact_tags` is non-empty, the
  receipt is HIGH-IMPACT and `parent_signature` MUST be present at
  the moment of verification. A conformant verifier rejects the
  receipt if the field is absent. The parent's signing path is
  expected to run before the action is observable to downstream
  consumers.
- **Async counter-sign.** When the action delegates to a child agent
  and `impact_tags` is empty, `parent_signature` MUST be present
  within MMD of the receipt's log inclusion timestamp. A conformant
  verifier consulting the receipt within MMD MAY accept the
  missing-parent-signature state with a warning; consulting after
  MMD with the field still absent is a rejection.

Outside these two cases, `parent_signature` is OPTIONAL.

### 16.2 Independence of evaluation

The defense in §12.5 assumes the parent's evaluation path is
genuinely independent of the child's. AERF v0.2 cannot enforce this
cryptographically; the `parent_evaluation_path_id` field is provided
so deployments can declare and audit independence out of band. A
common path ID across parent and child is not a verifier failure
but a monitor alert.

### 16.3 Canonical bytes signed

`parent_signature` covers exactly the canonical payload that
`signature` covered (§7 step 3). The strip set is the same. This
makes the parent counter-signature a strict ratchet: it cannot
attest to a different payload than the issuer signed.

## 17. Impact-tag registry

`impact_tags` is a closed-core, vendor-extensible array. The
presence of one or more tags marks the receipt as HIGH-IMPACT and
triggers the §3 conditional requirements.

### 17.1 Core tags (closed in v0.2)

| Tag | Semantic scope |
|-----|----------------|
| `HIPAA-PHI-WRITE` | The action writes Protected Health Information under HIPAA. |
| `HIPAA-PHI-DELETE` | The action deletes Protected Health Information under HIPAA. |
| `FINANCE-TRADE-EXEC` | The action executes a financial trade. |
| `FINANCE-DISBURSEMENT` | The action disburses funds. |
| `AGENT-AGENT-DELEGATION` | The action delegates work to a child agent. |
| `AGENT-EXTERNAL-CALL` | The action calls an external system outside the deployment's trust boundary. |

The core registry is closed in v0.2. Additions require a spec
revision. Closing the registry sidesteps a class of governance
attacks (a hostile registry editor cannot quietly redefine the
HIGH-IMPACT set).

### 17.2 Vendor namespace

Vendor extensions MUST use the prefix `x-{vendor}-` where `{vendor}`
is a lowercase ASCII alphanumeric token. The portion after the
prefix MUST match `[A-Za-z0-9_:-]+`. Downstream verifiers MUST treat
unrecognized vendor tags as informational; a deployment that
auto-elevates unknown tags to HIGH-IMPACT semantics is
non-conformant.

### 17.3 Governance

A working-group process for extending the core registry, and for
curating the conformant-log registry referenced in §15, is future
work and tracked as C-21.

---

## Appendix A. Non-normative annex on `enforcement_mode` (locked decision C-13)

Some implementations (notably the reference producer) emit a
`mode` field with values `enforce`, `warn`, or `shadow`, and an
`original_verdict` field, to support staged rollout of new policies.

**These fields are NOT part of the AERF specification.** They are
library-only conventions and conformant verifiers MUST NOT rely on
them. A producer that emits these fields remains conformant; a
verifier MAY ignore them entirely.

Future profiles MAY revisit this decision. For v0.2 the rationale
for excluding the fields is that *enforcement* is a deployment
property of the agent runtime, not a property of the receipt itself,
and conflating the two creates audit ambiguity ("did the policy fire,
or was the system in shadow mode?").

---

## Appendix B. Non-normative annex on carrier and insurance use cases

This annex describes how AERF's existing primitives — Plan receipts,
Evidence receipts, the hash chain, and `compliance_tags` — map onto
common insurance-carrier workflows. **It introduces no new normative
requirements.** Conformant producers and verifiers need do nothing
beyond what is specified in §1–§17.

### B.1 Underwriting intake

A Plan receipt defines the authorized scope of an agent — what tools
it may call, what policies govern it, and what `compliance_tags`
apply. Carriers can treat a submitted Plan receipt as a
machine-readable risk profile: the agent's declared permissions, the
policy hash binding it to a specific ruleset, and the `key_id`
identifying the signing party. This is independently verifiable
without relying on the insured's self-reported controls
documentation.

### B.2 Claims evidence

When a loss event occurs, the hash-chained receipt sequence
reconstructs exactly what the agent did, in what order, under what
policy, at what `observed_at` timestamp. The tamper-evident chain
means no party can retroactively alter the record. A carrier's
forensic team verifies the chain using only the public key and the
reference verifier — no AERF software, account, or service required.

### B.3 Coverage conditions

The `compliance_tags` field is the natural mapping point for coverage
conditions. Carriers can define tag namespaces that map to their
underwriting criteria alongside standard framework tags such as
AIUC-1, ISO/IEC 42001, or NIST AI RMF. This allows verification at
claims time that the agent operated within the declared scope that
was underwritten, without the spec encoding any single carrier's
policy terms.

Carriers wishing to define a carrier-specific receipt profile are
encouraged to open an issue in this repository. The AERF governance
process will track carrier profile proposals against C-21.

---

*End of v0.2.0-draft.1.*
