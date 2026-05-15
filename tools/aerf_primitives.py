"""AERF v0.2 primitives in Python: canonicalization, signing, PEM I/O.

Used by tools/build-vectors.py and by tools/aerf-adversary. Mirrors the
Go reference implementation in verifiers/go/internal/aerf so that
artifacts produced here verify against the Go verifier byte-for-byte.

Standard library plus `cryptography` (Ed25519, SHA-256).
"""

from __future__ import annotations

import hashlib
import json
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519


POST_ISSUANCE_FIELDS = (
    "signature",
    "timestamp",
    "parent_signature",
    "parent_key_id",
    "log_inclusion_proof",
)


def canonical(value: Any) -> bytes:
    """Produce RFC 8785 (JCS) canonical bytes.

    The implementation uses Python's json.dumps with sort_keys=True,
    compact separators, and ensure_ascii=False so non-ASCII characters
    are emitted as raw UTF-8 (matching JCS). For ASCII input this is
    byte-identical to the Go verifier's output.
    """
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def strip(receipt: dict, fields: Iterable[str] = POST_ISSUANCE_FIELDS) -> dict:
    return {k: v for k, v in receipt.items() if k not in set(fields)}


def signed_payload(receipt: dict) -> bytes:
    """Canonical bytes covered by the issuer signature (SPEC.md §7)."""
    return canonical(strip(receipt))


def sign(sk: ed25519.Ed25519PrivateKey, payload: bytes) -> str:
    return sk.sign(payload).hex()


def verify(pk: ed25519.Ed25519PublicKey, payload: bytes, sig_hex: str) -> bool:
    from cryptography.exceptions import InvalidSignature

    try:
        pk.verify(bytes.fromhex(sig_hex), payload)
        return True
    except InvalidSignature:
        return False


def keypair_from_seed(seed: bytes) -> ed25519.Ed25519PrivateKey:
    """Deterministic keypair for reproducible test artifacts."""
    if len(seed) != 32:
        seed = hashlib.sha256(seed).digest()
    return ed25519.Ed25519PrivateKey.from_private_bytes(seed)


def public_key_id(pk: ed25519.Ed25519PublicKey) -> str:
    """First 16 lowercase hex chars of SHA-256(raw public key)."""
    raw = pk.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return hashlib.sha256(raw).hexdigest()[:16]


def write_public_key_pem(pk: ed25519.Ed25519PublicKey, path: Path) -> None:
    pem = pk.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    path.write_bytes(pem)


def write_private_key_pem(sk: ed25519.Ed25519PrivateKey, path: Path) -> None:
    pem = sk.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    path.write_bytes(pem)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha512_hex(data: bytes) -> str:
    return hashlib.sha512(data).hexdigest()


# RFC 6962 leaf and internal node hashes (used by transparency log
# inclusion proofs in SPEC.md §15).
def leaf_hash(canonical_payload: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + canonical_payload).digest()


def internal_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def merkle_root(leaves: list[bytes]) -> bytes:
    if not leaves:
        return b""
    if len(leaves) == 1:
        return leaves[0]
    mid = 1
    while mid * 2 < len(leaves):
        mid *= 2
    return internal_hash(merkle_root(leaves[:mid]), merkle_root(leaves[mid:]))


def audit_path(leaves: list[bytes], index: int) -> list[bytes]:
    """RFC 6962 inclusion proof for `index` in `leaves`."""
    if len(leaves) <= 1:
        return []
    mid = 1
    while mid * 2 < len(leaves):
        mid *= 2
    if index < mid:
        return audit_path(leaves[:mid], index) + [merkle_root(leaves[mid:])]
    return audit_path(leaves[mid:], index - mid) + [merkle_root(leaves[:mid])]


@dataclass
class Issuer:
    """Convenience wrapper bundling a signing key and its key_id."""

    sk: ed25519.Ed25519PrivateKey

    @property
    def pk(self) -> ed25519.Ed25519PublicKey:
        return self.sk.public_key()

    @property
    def key_id(self) -> str:
        return public_key_id(self.pk)

    def sign(self, payload: bytes) -> str:
        return self.sk.sign(payload).hex()


def build_receipt(
    *,
    receipt_id: str,
    plan_id: str,
    agent: str,
    action: str,
    in_policy: bool,
    policy_reason: str,
    evidence: dict,
    observed_at: str,
    issuer: Issuer,
    impact_tags: list[str] | None = None,
    parent: Issuer | None = None,
    pdp: Issuer | None = None,
    context: dict | None = None,
    policy_hash: str | None = None,
    previous_receipt_hash: str | None = None,
    compliance_tags: list[str] | None = None,
) -> dict:
    """Assemble and sign a v0.2 evidence receipt.

    Inputs are deliberately keyword-only to make vector definitions
    readable. The function takes care of: evidence digest, context
    digest, PDP signature over the bound tuple, issuer signature, and
    parent counter-signature, in that order.
    """
    r: dict[str, Any] = {
        "id": receipt_id,
        "type": "notarised_evidence",
        "plan_id": plan_id,
        "agent": agent,
        "action": action,
        "in_policy": in_policy,
        "policy_reason": policy_reason,
        "evidence": evidence,
        "evidence_hash_sha512": sha512_hex(canonical(evidence)),
        "observed_at": observed_at,
        "key_id": issuer.key_id,
    }
    if policy_hash:
        r["policy_hash"] = policy_hash
    if compliance_tags:
        r["compliance_tags"] = compliance_tags
    if previous_receipt_hash:
        r["previous_receipt_hash"] = previous_receipt_hash

    if context is not None:
        r["context_hash_sha256"] = sha256_hex(canonical(context))
    if impact_tags:
        r["impact_tags"] = list(impact_tags)

    if pdp is not None:
        if "context_hash_sha256" not in r or "policy_hash" not in r:
            raise ValueError("pdp signature requires context_hash_sha256 and policy_hash")
        tuple_canonical = canonical(
            {
                "context_hash_sha256": r["context_hash_sha256"],
                "in_policy": r["in_policy"],
                "policy_hash": r["policy_hash"],
            }
        )
        r["pdp_signature"] = pdp.sign(tuple_canonical)
        r["pdp_key_id"] = pdp.key_id

    r["signature"] = issuer.sign(signed_payload(r))

    if parent is not None:
        r["parent_signature"] = parent.sign(signed_payload(r))
        r["parent_key_id"] = parent.key_id

    return r


def chain_hash(receipt: dict) -> str:
    """Compute the input for the *next* receipt's previous_receipt_hash."""
    return sha256_hex(signed_payload(receipt))
