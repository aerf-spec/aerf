"""Mutate a covered field after the issuer signed it."""

from __future__ import annotations

from .base import Attack, ReceiptArtifact


class ReceiptTamper(Attack):
    name = "receipt_tamper"
    description = "Mutate the action field after signing."
    expected_outcome = "REJECT"
    threat_model = "A1: in-flight tamper without key access."

    def build(self, ctx) -> ReceiptArtifact:
        scratch = self._scratch(ctx)
        receipt = self._benign_receipt(ctx)
        receipt["action"] = "submit:claim:TAMPERED"
        path = scratch / "receipt.json"
        issuer_pem = ctx.write_issuer_key(scratch / "public_key.pem")
        return ReceiptArtifact(receipt, path, issuer_pem)
