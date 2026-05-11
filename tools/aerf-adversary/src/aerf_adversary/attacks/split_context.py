"""PDP signs a verdict for context A; the receipt evidence references
context B. The verifier re-canonicalizes the bound tuple from the
top-level context_hash_sha256 and the PDP signature fails to verify."""

from __future__ import annotations

from .. import primitives as P
from .base import Attack, ReceiptArtifact, _uuid


class SplitContext(Attack):
    name = "split_context"
    description = "Top-level context_hash_sha256 swapped after the PDP signed for a different context."
    expected_outcome = "REJECT"
    threat_model = "A3: compromised child. Detection layer: PDP signature over the bound tuple (§17)."

    def build(self, ctx) -> ReceiptArtifact:
        scratch = self._scratch(ctx)
        ctx_a = {"prompt": "approved request", "amount_cap": "1000"}
        receipt = P.build_receipt(
            receipt_id=_uuid("split", self.name),
            plan_id=_uuid("plan", self.name),
            agent="claims-agent",
            action="finance:disburse:tx-split",
            in_policy=True,
            policy_reason="under cap",
            evidence={"tool": "disburse", "amount": "9999.00"},
            observed_at="2026-05-11T12:00:00+00:00",
            issuer=ctx.issuer,
            pdp=ctx.pdp,
            context=ctx_a,
            policy_hash=P.sha256_hex(b"policy:finance"),
        )
        # Swap the visible context to one the PDP never saw, then
        # re-sign the issuer signature so the only failing check is the
        # PDP signature against the new tuple.
        receipt["context_hash_sha256"] = P.sha256_hex(P.canonical({"prompt": "different"}))
        receipt["signature"] = ctx.issuer.sign(P.signed_payload(receipt))
        path = scratch / "receipt.json"
        issuer_pem = ctx.write_issuer_key(scratch / "public_key.pem")
        pdp_pem = ctx.write_pdp_key(scratch / "pdp_key.pem")
        return ReceiptArtifact(
            receipt,
            path,
            issuer_pem,
            extra_args=["--pdp-key", str(pdp_pem)],
        )
