"""Forge the STH signature on a log inclusion proof using a key the
verifier does not trust. Detected by §10.1 step 8."""

from __future__ import annotations

from .. import primitives as P
from .base import Attack, ReceiptArtifact


class LogSpoofing(Attack):
    name = "log_spoofing"
    description = "STH signed by an untrusted log key."
    expected_outcome = "REJECT"
    threat_model = "A1: forged log STH. Detection layer: STH signature verification (§15)."

    def build(self, ctx) -> ReceiptArtifact:
        scratch = self._scratch(ctx)
        receipt = self._benign_receipt(ctx)
        leaf = P.leaf_hash(P.signed_payload(receipt))
        # Build a one-leaf tree so audit_path is empty and root == leaf.
        sth = {
            "tree_size": 1,
            "root_hash": leaf.hex(),
            "timestamp": "2026-05-11T12:00:00+00:00",
        }
        # Sign with the rogue key, not the log key.
        sth_sig = ctx.rogue.sign(P.canonical(sth))
        receipt["log_inclusion_proof"] = {
            "log_id": "forged-log",
            "leaf_hash": leaf.hex(),
            "leaf_index": 0,
            "tree_size": 1,
            "audit_path": [],
            "sth": sth,
            "sth_signature": sth_sig,
        }
        path = scratch / "receipt.json"
        issuer_pem = ctx.write_issuer_key(scratch / "public_key.pem")
        log_pem = ctx.write_log_key(scratch / "log_key.pem")
        return ReceiptArtifact(
            receipt,
            path,
            issuer_pem,
            extra_args=["--log-key", str(log_pem), "--require-log"],
        )
