"""HIGH-IMPACT receipt with the parent counter-signature missing.
The verifier rejects under §3 regardless of MMD, since the field is
absent at verification time. This is the receipt-layer manifestation
of an MMD-window failure for a delegated action."""

from __future__ import annotations

from .. import primitives as P
from .base import Attack, ReceiptArtifact, _uuid


class MMDViolation(Attack):
    name = "mmd_violation"
    description = "HIGH-IMPACT receipt examined after MMD with parent_signature still absent."
    expected_outcome = "REJECT"
    threat_model = "A1 + A10: parent suppression past MMD. Detection layer: §3 conformance."

    def build(self, ctx) -> ReceiptArtifact:
        scratch = self._scratch(ctx)
        receipt = P.build_receipt(
            receipt_id=_uuid("mmd", self.name),
            plan_id=_uuid("plan", self.name),
            agent="claims-agent",
            action="agent:delegate:child-001",
            in_policy=True,
            policy_reason="delegation",
            evidence={"tool": "delegate", "child": "child-001"},
            observed_at="2026-05-11T12:00:00+00:00",
            issuer=ctx.issuer,
            impact_tags=["AGENT-AGENT-DELEGATION"],
            pdp=ctx.pdp,
            context={"prompt": "delegate work"},
            policy_hash=P.sha256_hex(b"policy:delegation"),
        )
        receipt.pop("parent_signature", None)
        receipt.pop("parent_key_id", None)
        path = scratch / "receipt.json"
        issuer_pem = ctx.write_issuer_key(scratch / "public_key.pem")
        return ReceiptArtifact(receipt, path, issuer_pem)
