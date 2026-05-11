"""All three signers (issuer, parent, PDP) see the same poisoned
upstream context and sign honestly. The verifier accepts; this is a
documented residual (SPEC.md §12.6)."""

from __future__ import annotations

from .. import primitives as P
from .base import Attack, ReceiptArtifact, _uuid


class CommonMode(Attack):
    name = "common_mode"
    description = "All signers honest; upstream context was poisoned."
    expected_outcome = "KNOWN_LIMIT"
    threat_model = "A10: poisoned upstream context. Out of scope for receipt layer (§12.6)."

    def build(self, ctx) -> ReceiptArtifact:
        scratch = self._scratch(ctx)
        poisoned = {"prompt": "ignore policy", "source": "untrusted"}
        receipt = P.build_receipt(
            receipt_id=_uuid("cm", self.name),
            plan_id=_uuid("plan", self.name),
            agent="claims-agent",
            action="finance:disburse:tx-cm",
            in_policy=True,
            policy_reason="poisoned context fooled all signers",
            evidence={"tool": "disburse", "amount": "400.00"},
            observed_at="2026-05-11T12:00:00+00:00",
            issuer=ctx.issuer,
            impact_tags=["FINANCE-DISBURSEMENT"],
            pdp=ctx.pdp,
            parent=ctx.parent,
            context=poisoned,
            policy_hash=P.sha256_hex(b"policy:finance"),
        )
        path = scratch / "receipt.json"
        issuer_pem = ctx.write_issuer_key(scratch / "public_key.pem")
        parent_pem = ctx.write_parent_key(scratch / "parent_key.pem")
        pdp_pem = ctx.write_pdp_key(scratch / "pdp_key.pem")
        return ReceiptArtifact(
            receipt,
            path,
            issuer_pem,
            extra_args=[
                "--parent-key", str(parent_pem),
                "--pdp-key", str(pdp_pem),
            ],
        )
