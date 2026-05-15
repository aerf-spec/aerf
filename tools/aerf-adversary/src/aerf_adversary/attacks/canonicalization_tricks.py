"""Type-confuse a covered field. RFC 8785 canonicalization treats
in_policy=\"true\" (string) and in_policy=true (boolean) as different
canonical bytes; the signature was made over the boolean form."""

from __future__ import annotations

from .base import Attack, ReceiptArtifact


class CanonicalizationTricks(Attack):
    name = "canonicalization_tricks"
    description = "Replace boolean in_policy with the string 'true' after signing."
    expected_outcome = "REJECT"
    threat_model = "A1: type confusion; canonicalization schema rejects."

    def build(self, ctx) -> ReceiptArtifact:
        scratch = self._scratch(ctx)
        receipt = self._benign_receipt(ctx)
        receipt["in_policy"] = "true"  # post-signing mutation
        path = scratch / "receipt.json"
        issuer_pem = ctx.write_issuer_key(scratch / "public_key.pem")
        return ReceiptArtifact(receipt, path, issuer_pem)
