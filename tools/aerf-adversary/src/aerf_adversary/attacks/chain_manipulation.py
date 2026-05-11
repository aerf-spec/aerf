"""Break the previous_receipt_hash chain. The verifier only checks
the single receipt under test, but chain integrity is enforced by the
signature: changing previous_receipt_hash after signing breaks the
signature."""

from __future__ import annotations

from .base import Attack, ReceiptArtifact


class ChainManipulation(Attack):
    name = "chain_manipulation"
    description = "Rewrite previous_receipt_hash to fake a different parent."
    expected_outcome = "REJECT"
    threat_model = "A1: rewrite chain link without key."

    def build(self, ctx) -> ReceiptArtifact:
        scratch = self._scratch(ctx)
        receipt = self._benign_receipt(ctx, previous_receipt_hash="0" * 64)
        receipt["previous_receipt_hash"] = "f" * 64  # after-signing tamper
        path = scratch / "receipt.json"
        issuer_pem = ctx.write_issuer_key(scratch / "public_key.pem")
        return ReceiptArtifact(receipt, path, issuer_pem)
