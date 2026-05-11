"""Strip impact_tags from a receipt that should have been HIGH-IMPACT.
The verifier sees a non-HIGH-IMPACT receipt and does not insist on
parent or PDP signatures. This is a documented residual (SPEC.md
§12.7)."""

from __future__ import annotations

from .base import Attack, ReceiptArtifact


class TagStripping(Attack):
    name = "tag_stripping"
    description = "Drop impact_tags before signing to evade HIGH-IMPACT rules."
    expected_outcome = "KNOWN_LIMIT"
    threat_model = "A3: receipt-layer cannot detect; defense is upstream PEP (OP-5)."

    def build(self, ctx) -> ReceiptArtifact:
        scratch = self._scratch(ctx)
        # No impact_tags despite being a finance disbursement.
        receipt = self._benign_receipt(
            ctx,
            action="finance:disburse:tx-strip",
        )
        path = scratch / "receipt.json"
        issuer_pem = ctx.write_issuer_key(scratch / "public_key.pem")
        return ReceiptArtifact(receipt, path, issuer_pem)
