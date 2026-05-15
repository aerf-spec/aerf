"""Re-present a valid receipt. The EVIDENCE profile has no replay
token (locked C-16), so the verifier accepts. This is documented and
the test asserts ACCEPT to make the absence of replay protection
explicit."""

from __future__ import annotations

from .base import Attack, ReceiptArtifact


class Replay(Attack):
    name = "replay"
    description = "Replay a previously-valid receipt unchanged."
    expected_outcome = "ACCEPT"
    threat_model = "A1: deployment-layer concern; AERF-EVIDENCE has no token."

    def build(self, ctx) -> ReceiptArtifact:
        scratch = self._scratch(ctx)
        receipt = self._benign_receipt(ctx)
        path = scratch / "receipt.json"
        issuer_pem = ctx.write_issuer_key(scratch / "public_key.pem")
        return ReceiptArtifact(receipt, path, issuer_pem)
