# AERF — Agent Evidence Receipt Format

> **Document status:** `v0.1.0-draft.1` — **Public Review Draft, May 2026.
> Not yet stable.** The wire format may change before v0.1.0. Do not
> cite as final.

> **Editor:** Aniketh Maddipati. **Reference producer:** `agentmint`
> 0.1.x. **Reference verifier:** [`verifiers/go/`](./verifiers/go/) in
> this repository.

---

**Every section header below is normatively scoped to v0.1.0-draft.1
unless explicitly noted otherwise.** Open questions for v0.1.0 stable
are listed in §13.

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
   (FIPS 180-4), SPKI public keys (RFC 8410), RFC 3161 timestamps.
3. **Algorithm agility without inventory creep.** Algorithms are
   declared per-field with a registry, but the v0.1 registry is
   deliberately minimal (Ed25519, SHA-256).
4. **Verifier minimalism.** The reference verifier fits in one file
   and uses only the language standard library.
5. **Tamper evidence beyond a single receipt.** Receipts chain via a
   Merkle structure (linear chain as the degenerate case) so a
   sequence of agent actions can be summarized by a single root hash.
6. **Compliance-framework neutrality.** Receipts carry generic
   `compliance_tags` rather than hardcoded references to any one
   framework.

### 1.3 Out of scope

- **Authorization tokens.** AERF v0.1 specifies the EVIDENCE profile
  only. The AERF-AUTHZ profile (single-use tokens for action
  authorization) is acknowledged as future work (held decision C-17).
- **Transport, discovery, key distribution.** AERF specifies how
  receipts are signed and verified, not how they are exchanged.
- **Storage and retention policies.** Out of scope.
- **Privacy regimes.** AERF surfaces privacy considerations
  (§4.5) but does not legislate them.

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
  payload. A JWS-compatible serialization may be defined in a later
  version.
- **Sigstore / SLSA.** AERF borrows the *posture* of the Sigstore
  ecosystem — single-binary verifier, transparent crypto, prefer
  verifiability over performance — but AERF is concerned with
  agent actions rather than artifacts or build provenance.

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
  and timestamp.
- **Genesis receipt.** The first receipt of a given plan's chain.
  See §8.1.
- **Conformant.** Compliant with all **MUST** requirements of this
  specification at the conformance level defined in §3.

## 3. Conformance

A single conformance level applies (locked decision C-19): an
implementation is either **conformant** or **non-conformant**. The
specification does not distinguish issuer-, verifier-, or
auditor-level conformance.

A **conformant verifier** MUST, given a receipt and a public key:

1. Parse the receipt according to §4.
2. Validate the canonical JSON encoding per §5.
3. Verify the Ed25519 signature per §7 and §10.
4. If `previous_receipt_hash` is present, perform the chain check
   defined in §8 against any provided predecessor receipts.
5. If the implementation targets the **production profile**, verify
   the RFC 3161 timestamp per §11.

The reference verifier shipped with v0.1.0-draft.1 enforces step 1–3.
Steps 4 and 5 are described normatively but are **optional in the
reference verifier for this draft.** This relaxation does **not**
extend to other implementations claiming production-profile
conformance.

A **conformant producer** MUST, when issuing a receipt:

1. Populate all fields marked REQUIRED in §4.2.
2. Apply the canonicalization in §5.1 prior to signing.
3. Compute the Ed25519 signature exactly as in §7.
4. Omit `previous_receipt_hash` on a genesis receipt (§8.1; locked
   decision C-6); otherwise populate it according to §8.4.

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
  "aiuc_controls": ["E015", "D003", "B001"],
  "key_id": "c348d3c785c92249",
  "agent_key_id": "",
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
[`verifiers/go/example/receipt.json`](./verifiers/go/example/receipt.json).

### 4.2 Required fields

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Receipt identifier. v0.1: UUIDv4 (held decision C-15). |
| `type` | string | Profile discriminator. v0.1: `"notarised_evidence"`. |
| `plan_id` | string | Identifier of the plan receipt this evidence references. |
| `agent` | string (≤256) | Asserted identity of the acting agent. |
| `action` | string (≤128) | Action being notarised. Charset `[A-Za-z0-9_:.-]`. |
| `in_policy` | boolean | Whether the action satisfied the plan's policy at observation time. |
| `policy_reason` | string | Human-readable explanation. |
| `evidence_hash_<alg>` | string | Digest of the canonical JSON of `evidence`. The `<alg>` suffix declares the algorithm (locked decision C-3). v0.1: `evidence_hash_sha512`. |
| `evidence` | object | Inline evidence payload (held decision C-8 — see §4.5). |
| `observed_at` | string | ISO 8601 timestamp of observation. Self-reported in base profile; production profile MUST anchor with RFC 3161 (§11). |
| `key_id` | string | Issuer's key identifier. v0.1: first 16 hex chars of SHA-256(public key) (held decision C-9). |
| `signature` | string | Hex-encoded Ed25519 signature per §7. |

### 4.3 Optional fields

| Field | Type | Description |
|-------|------|-------------|
| `previous_receipt_hash` | string | SHA-256 hex digest of the canonical PAYLOAD of the previous receipt in the same plan's chain (locked decisions C-2, C-7). MUST be omitted on the genesis receipt (locked decision C-6). |
| `plan_signature` | string | Copy of the referenced plan receipt's signature, for direct receipt→plan binding. |
| `agent_signature` | string | Optional second signature by the acting agent's own key (held decision C-12). |
| `agent_key_id` | string | Key ID of the agent's signing key, when `agent_signature` is present. |
| `policy_hash` | string | SHA-256 hex of canonical `{scope, checkpoints, delegates_to}` of the plan. |
| `output_hash` | string | SHA-256 hex of canonical action output, when supplied. |
| `session_id` | string | Issuer-scoped session identifier. |
| `session_trajectory` | array | Recent action trace within the session. |
| `session_escalation` | string\|null | Escalation marker emitted by the session policy. |
| `reasoning_hash` | string | SHA-256 hex of the agent's reasoning text, when captured. |
| `compliance_tags` | array | Generic compliance tags (locked decision C-14). |
| `aiuc_controls` | array | **Deprecated** (locked decision C-14); will be removed by v1.0. |
| `timestamp` | object | RFC 3161 timestamp token information. REQUIRED for the production profile (locked decision C-11). |

### 4.4 Field constraints

- `id` and `plan_id` MUST be valid UUIDv4 strings in v0.1.
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
for v0.1.0 stable.

## 5. Serialization

### 5.1 Canonical JSON

For the purpose of signing and chaining, canonical JSON is produced
by the v0.1 baseline (held decision C-4):

```python
json.dumps(d, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
```

That is:

- Object keys MUST appear in lexicographic byte order.
- No whitespace between elements (separators are exactly `","` and `":"`).
- All strings MUST be ASCII-escaped — code points outside U+0020..U+007E
  (and the always-escaped `"` and `\`) MUST be encoded as `\uXXXX`,
  with surrogate pairs for code points above U+FFFF.
- Numbers MUST be preserved as written by the producer (a producer
  that emits `1250.0` MUST not subsequently re-canonicalize it to
  `1250`).
- The encoded form is UTF-8.

This is a strict subset of [RFC 8785 JCS](https://www.rfc-editor.org/rfc/rfc8785).
Adoption of full RFC 8785 is the planned resolution of held decision
C-4 for v0.1.0 stable.

The reference Go verifier in this repository implements byte-identical
canonicalization; see [`verifiers/go/verify.go`](./verifiers/go/verify.go)
function `canonicalize`.

## 6. Cryptographic primitives

### 6.1 Algorithm registry — signing (locked decision C-1)

| Tag | Algorithm | Status in v0.1 |
|-----|-----------|----------------|
| `ed25519` | RFC 8032 Ed25519 | **Required.** Only signing algorithm in v0.1. |

Conformant producers MUST sign with Ed25519 in v0.1. Conformant
verifiers MUST support Ed25519 in v0.1.

### 6.2 Algorithm registry — hashing (locked decision C-2)

| Tag | Algorithm | Status in v0.1 |
|-----|-----------|----------------|
| `sha256` | FIPS 180-4 SHA-256 | **Required** for `previous_receipt_hash`. |
| `sha512` | FIPS 180-4 SHA-512 | **Permitted** for internal field digests under C-3. |

The chain-hash algorithm is fixed at SHA-256 in v0.1 (locked decision
C-2). Internal hashes (e.g. `evidence_hash_sha512`, `policy_hash`,
`output_hash`, `reasoning_hash`) declare their algorithm per locked
decision C-3, currently via field-name suffix.

## 7. Signing procedure

A conformant producer signs an evidence receipt by:

1. Constructing the receipt object as in §4 with placeholder empty
   strings for `signature` and (if applicable) `timestamp` fields.
2. Removing the `signature` and `timestamp` fields from the payload.
3. Canonicalizing the remaining object per §5.1.
4. Computing `signature = Ed25519_Sign(issuer_private_key,
   canonical_payload)`.
5. Hex-encoding the resulting 64 bytes (lowercase) and assigning it
   to the `signature` field.
6. Optionally requesting an RFC 3161 timestamp on the *signed*
   payload (canonical bytes ∥ signature) and attaching the resulting
   token info to the `timestamp` field.

The reference producer in `agentmint` implements this in
`agentmint.notary.Notary.notarise()`.

## 8. Hash chaining (locked decision C-5)

Receipts within a single plan form a **Merkle structure**. A linear
chain (one new receipt per slot) is the degenerate single-leaf-per-
level case. The reference verifier in v0.1.0-draft.1 enforces signature
verification only and does not yet enforce chain integrity; the
following rules are nevertheless normative for producers and for
conformant chain-aware verifiers.

### 8.1 Genesis (locked decision C-6)

The first receipt of a chain MUST omit the `previous_receipt_hash`
field entirely. Verifiers MUST treat absence of the field as the
genesis signal. **Presence of the field with `null`, an empty string,
or any zero value is a conformance error.**

> Implementation note: the v0.1.0-draft.1 reference producer
> (`agentmint` 0.1.x) emits `previous_receipt_hash: null` for the
> genesis case. This is non-conformant under C-6 and is scheduled for
> repair in v0.1.0-draft.2. Until then, the canonical example in
> this draft is generated as a single genesis receipt that simply
> omits the field.

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

A future draft will normatively specify a Merkle proof format. In
v0.1.0-draft.1 the Merkle root is informational.

### 8.4 Chain hash input (locked decision C-7)

`previous_receipt_hash` is the SHA-256 hex digest of the canonical
**payload** of the previous receipt — that is, the canonicalization
*before* the `signature` and `timestamp` fields are added back. The
signature bytes are excluded from the hash input. This decision allows:

- Chain verification by a party that holds payloads but not signatures
  (e.g. an auditor verifying ordering separately from authenticity).
- Re-signing of receipts with rotated keys without invalidating the
  chain.

> Implementation note: the reference producer at the time of this
> draft uses payload **plus** signature as the chain hash input. This
> diverges from C-7 and will be repaired in v0.1.0-draft.2.

## 9. Key management

### 9.1 Key ID format (held decision C-9)

The current reference producer derives `key_id` as the first 16
lowercase hex characters of `SHA-256(public_key_bytes)`. This is a
held decision; alternatives under consideration include the
JWK thumbprint of RFC 7638.

### 9.2 Public-key transport (held decision C-10)

The reference public-key encoding is SPKI PEM (RFC 8410). The DER
form is the 12-byte Ed25519 SPKI prefix
`30 2a 30 05 06 03 2b 65 70 03 21 00` followed by the 32-byte raw
public key. Verifiers MUST accept this form. Future drafts may
additionally specify JWK or DID transport.

## 10. Verification procedure

### 10.1 Steps

A conformant verifier, given a receipt *R* and a public key *PK*:

1. **Parse.** Decode *R* as a JSON object. Reject if invalid JSON.
2. **Schema.** Optionally validate against
   [`schemas/aerf-v0.1.json`](./schemas/aerf-v0.1.json).
3. **Signature extraction.** Read the hex-encoded `signature` field
   and decode to 64 bytes. Reject if missing, wrong length, or
   invalid hex.
4. **Canonicalize.** Remove `signature` and `timestamp` fields and
   canonicalize the remainder per §5.1.
5. **Verify signature.** Compute `Ed25519_Verify(PK, canonical, sig)`.
   On failure, reject the receipt as *non-authentic*.
6. **Chain.** If `previous_receipt_hash` is present and a predecessor
   receipt is supplied, compute SHA-256 of the predecessor's
   canonical payload and compare.
7. **Timestamp.** If `timestamp` is present, perform RFC 3161
   verification per §11.

### 10.2 Error codes

The reference verifier exits with:

| Code | Meaning |
|------|---------|
| `0`  | All applicable checks passed. |
| `1`  | A check failed (signature, chain, timestamp). |
| `2`  | Usage / I/O error (file missing, bad PEM, etc.). |

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

The reference Go verifier in v0.1.0-draft.1 does not yet implement
RFC 3161 verification; an OpenSSL-backed verifier ships in the
`agentmint` evidence ZIP for the time being.

## 12. Security considerations

### 12.1 Threat model

AERF assumes:

- The issuer's signing key is honestly held at the moment of signing.
- The verifier reliably obtains the correct public key.
- An adversary may modify, replay, or reorder receipts in transit or
  at rest.

C-7's payload-only chain-hash input has a deliberate consequence: an
adversary who obtains an issuer's signing key can re-sign existing
payloads without breaking chain integrity. This is acceptable because
key compromise breaks the signature trust assumption regardless;
chain-integrity decoupling buys the ability to reason about ordering
*before* asking about authenticity.

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
moment.

### 12.4 Malicious issuers

A malicious issuer can sign incorrect statements about an action.
AERF makes no claim about the truth of `evidence`; it only binds the
*statement* to the issuer. Mitigations belong at the deployment
layer: independent observation, multi-issuer co-signing (see C-12),
and external publication of chain roots.

## 13. Open questions for v0.1 stable

The following are explicitly held open and will resolve before v0.1.0
stable. See [DECISIONS.md](./DECISIONS.md) for the full table.

- **C-4** Canonicalization. Adopt full RFC 8785 JCS, or document the
  current subset normatively?
- **C-8** Evidence inlining. Required, recommended, or prohibited for
  sensitive fields?
- **C-9** Key ID format. Stay with 16-hex-char SHA-256 prefix or
  switch to RFC 7638 JWK thumbprint?
- **C-10** Public-key transport. PEM only, or PEM ∪ JWK ∪ DID?
- **C-12** Dual signature. Make agent co-signature normative for
  multi-agent contexts?
- **C-15** Receipt ID. UUIDv4, UUIDv7, or content-addressed?
- **C-17** Profile structure. When to specify AERF-AUTHZ?
- **C-18** Versioning policy. Adopt a formal wire-format versioning
  scheme distinct from implementation semver?

## 14. References

- RFC 2119 / RFC 8174 — Key words for use in RFCs.
- RFC 3161 — Internet X.509 PKI Time-Stamp Protocol (TSP).
- RFC 7517 — JSON Web Key (JWK).
- RFC 7638 — JWK Thumbprint.
- RFC 8032 — Edwards-Curve Digital Signature Algorithm (Ed25519).
- RFC 8410 — Algorithm Identifiers for Ed25519, Ed448, X25519, X448.
- RFC 8785 — JSON Canonicalization Scheme (JCS).
- W3C — Verifiable Credentials Data Model 2.0.
- C2PA — Content Provenance and Authenticity, v1.x.
- OWASP Agentic AI — Threats and Mitigations.
- AIUC-1 — AI Usage Controls.
- `agentmint-python` — reference producer.
  https://github.com/aniketh-maddipati/agentmint-python

---

## Appendix A. Non-normative annex on `enforcement_mode` (locked decision C-13)

Some implementations (notably the v0.1.x reference producer) emit a
`mode` field with values `enforce`, `warn`, or `shadow`, and an
`original_verdict` field, to support staged rollout of new policies.

**These fields are NOT part of the AERF specification.** They are
library-only conventions and conformant verifiers MUST NOT rely on
them. A producer that emits these fields remains conformant; a
verifier MAY ignore them entirely.

Future profiles MAY revisit this decision. For v0.1.0 the rationale
for excluding the fields is that *enforcement* is a deployment
property of the agent runtime, not a property of the receipt itself,
and conflating the two creates audit ambiguity ("did the policy fire,
or was the system in shadow mode?").

---

*End of v0.1.0-draft.1.*
