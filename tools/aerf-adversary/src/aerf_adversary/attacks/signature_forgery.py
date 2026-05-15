"""Sign the canonical payload with a rogue key the verifier does not
trust. The expected verifier path is §10.1 step 5 (issuer signature
verification)."""

from __future__ import annotations

from .. import primitives as P
from .base import Attack, ReceiptArtifact, _uuid


class SignatureForgery(Attack):
    name = "signature_forgery"
    description = "Rogue keypair signs an otherwise-valid receipt."
    expected_outcome = "REJECT"
    threat_model = "A1: network attacker without access to the issuer key."

    def build(self, ctx) -> ReceiptArtifact:
        scratch = self._scratch(ctx)
        receipt = P.build_receipt(
            receipt_id=_uuid("forge", self.name),
            plan_id=_uuid("plan", self.name),
            agent="claims-agent",
            action="submit:claim:forge",
            in_policy=True,
            policy_reason="forged",
            evidence={"tool": "submit-claim"},
            observed_at="2026-05-11T12:00:00+00:00",
            issuer=ctx.rogue,  # rogue signs
        )
        # Replace the issuer key_id with the legitimate issuer's so the
        # only mismatch is the signature itself.
        receipt["key_id"] = ctx.issuer.key_id
        receipt_path = scratch / "receipt.json"
        issuer_pem = ctx.write_issuer_key(scratch / "public_key.pem")
        return ReceiptArtifact(receipt, receipt_path, issuer_pem)
