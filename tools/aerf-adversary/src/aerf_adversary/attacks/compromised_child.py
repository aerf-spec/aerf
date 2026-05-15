"""The C-12 base case: a compromised lower agent issues a
HIGH-IMPACT receipt asserting in_policy=true with no parent
counter-signature. The verifier MUST reject because impact_tags is
non-empty (SPEC.md §3, §16)."""

from __future__ import annotations

from .. import primitives as P
from .base import Attack, ReceiptArtifact, _uuid


class CompromisedChild(Attack):
    name = "compromised_child"
    description = "Child issues a HIGH-IMPACT receipt with no parent_signature."
    expected_outcome = "REJECT"
    threat_model = "A3: compromised lower agent. Detection layer: parent counter-sign (§16)."

    def build(self, ctx) -> ReceiptArtifact:
        scratch = self._scratch(ctx)
        # PDP signs honestly; parent is missing.
        context = {"prompt": "operator request", "source": "trusted"}
        receipt = P.build_receipt(
            receipt_id=_uuid("c12", self.name),
            plan_id=_uuid("plan", self.name),
            agent="claims-agent",
            action="finance:disburse:tx-c12",
            in_policy=True,
            policy_reason="malicious self-attestation",
            evidence={"tool": "disburse", "amount": "10000.00"},
            observed_at="2026-05-11T12:00:00+00:00",
            issuer=ctx.issuer,
            impact_tags=["FINANCE-DISBURSEMENT"],
            pdp=ctx.pdp,
            context=context,
            policy_hash=P.sha256_hex(b"policy:finance"),
        )
        # Deliberately strip the parent signature (it would not exist
        # in the actual attack because the parent never saw the action).
        receipt.pop("parent_signature", None)
        receipt.pop("parent_key_id", None)
        path = scratch / "receipt.json"
        issuer_pem = ctx.write_issuer_key(scratch / "public_key.pem")
        pdp_pem = ctx.write_pdp_key(scratch / "pdp_key.pem")
        return ReceiptArtifact(
            receipt,
            path,
            issuer_pem,
            extra_args=["--pdp-key", str(pdp_pem)],
        )
