"""Attack ABC and the on-disk artifact produced by build()."""

from __future__ import annotations

import datetime as dt
import json
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal, TYPE_CHECKING

from .. import primitives as P

if TYPE_CHECKING:
    from ..runner import AttackContext


@dataclass
class ReceiptArtifact:
    """Files produced by an attack, plus any extra verifier flags."""

    receipt: dict
    receipt_path: Path
    issuer_key_path: Path
    extra_args: list[str] = field(default_factory=list)

    def write(self) -> None:
        self.receipt_path.parent.mkdir(parents=True, exist_ok=True)
        self.receipt_path.write_text(json.dumps(self.receipt, indent=2))


class Attack(ABC):
    """Each subclass produces one malicious receipt artifact and
    documents which verifier check (signature / chain / parent / pdp /
    log / none) the spec relies on to catch it."""

    name: str = ""
    description: str = ""
    expected_outcome: Literal["REJECT", "ACCEPT", "KNOWN_LIMIT"] = "REJECT"
    threat_model: str = ""

    @abstractmethod
    def build(self, ctx: "AttackContext") -> ReceiptArtifact:
        ...

    # -- helpers shared across attacks --

    def _scratch(self, ctx: "AttackContext") -> Path:
        d = ctx.workdir / self.name
        d.mkdir(parents=True, exist_ok=True)
        return d

    def _benign_receipt(self, ctx: "AttackContext", **overrides) -> dict:
        defaults = dict(
            receipt_id=_uuid("benign", self.name),
            plan_id=_uuid("plan", self.name),
            agent="claims-agent",
            action="submit:claim:CLM-9999",
            in_policy=True,
            policy_reason="matched scope",
            evidence={"tool": "submit-claim", "claim_id": "CLM-9999"},
            observed_at="2026-05-11T12:00:00+00:00",
            issuer=ctx.issuer,
        )
        defaults.update(overrides)
        return P.build_receipt(**defaults)


def _uuid(*parts: str) -> str:
    h = P.sha256_hex("|".join(parts).encode())
    return f"{h[0:8]}-{h[8:12]}-4{h[13:16]}-8{h[17:20]}-{h[20:32]}"
