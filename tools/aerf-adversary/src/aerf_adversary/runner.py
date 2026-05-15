"""Subprocess runner: hands a malicious receipt to a verifier and
records whether the verifier accepted or rejected it."""

from __future__ import annotations

import json
import os
import shlex
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal, Optional

from . import primitives as P
from .attacks.base import Attack, ReceiptArtifact


Outcome = Literal["ACCEPT", "REJECT"]


@dataclass
class AttackContext:
    """Shared key material used to build malicious receipts.

    Built once per run; each attack receives its own scratch directory
    under `workdir` so artifacts do not collide.
    """

    workdir: Path
    issuer: P.Issuer = field(init=False)
    parent: P.Issuer = field(init=False)
    pdp: P.Issuer = field(init=False)
    log: P.Issuer = field(init=False)
    rogue: P.Issuer = field(init=False)

    def __post_init__(self) -> None:
        self.issuer = P.Issuer(P.keypair_from_seed(b"adversary-issuer-fixed-seed-0\x00\x00\x00"))
        self.parent = P.Issuer(P.keypair_from_seed(b"adversary-parent-fixed-seed-0\x00\x00\x00"))
        self.pdp = P.Issuer(P.keypair_from_seed(b"adversary-pdp-fixed-seed-0001\x00\x00\x00"))
        self.log = P.Issuer(P.keypair_from_seed(b"adversary-log-fixed-seed-0001\x00\x00\x00"))
        self.rogue = P.Issuer(P.keypair_from_seed(b"adversary-rogue-fixed-seed-00\x00\x00\x00"))
        self.workdir.mkdir(parents=True, exist_ok=True)

    def write_issuer_key(self, path: Path) -> Path:
        P.write_public_key_pem(self.issuer.pk, path)
        return path

    def write_parent_key(self, path: Path) -> Path:
        P.write_public_key_pem(self.parent.pk, path)
        return path

    def write_pdp_key(self, path: Path) -> Path:
        P.write_public_key_pem(self.pdp.pk, path)
        return path

    def write_log_key(self, path: Path) -> Path:
        P.write_public_key_pem(self.log.pk, path)
        return path


@dataclass
class AttackResult:
    name: str
    description: str
    expected: str  # REJECT | ACCEPT | KNOWN_LIMIT
    actual: Outcome
    matches_expected: bool
    stderr: str
    exit_code: int
    artifact_path: Path
    threat_model: str = ""

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "description": self.description,
            "expected": self.expected,
            "actual": self.actual,
            "matches_expected": self.matches_expected,
            "exit_code": self.exit_code,
            "stderr": self.stderr,
            "artifact": str(self.artifact_path),
            "threat_model": self.threat_model,
        }


def run_against_verifier(
    verifier_cmd: list[str],
    attack: Attack,
    ctx: AttackContext,
    timeout: float = 15.0,
) -> AttackResult:
    """Build the attack artifact, invoke the verifier, classify the
    outcome, and produce an AttackResult.
    """
    artifact = attack.build(ctx)
    artifact.write()

    cmd = list(verifier_cmd) + list(artifact.extra_args) + [
        str(artifact.receipt_path),
        str(artifact.issuer_key_path),
    ]
    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
        env={**os.environ},
    )
    actual: Outcome = "ACCEPT" if proc.returncode == 0 else "REJECT"
    expected = attack.expected_outcome
    matches = expected == "KNOWN_LIMIT" or expected == actual

    return AttackResult(
        name=attack.name,
        description=attack.description,
        expected=expected,
        actual=actual,
        matches_expected=matches,
        stderr=proc.stderr,
        exit_code=proc.returncode,
        artifact_path=artifact.receipt_path,
        threat_model=getattr(attack, "threat_model", ""),
    )


def parse_verifier(spec: str) -> list[str]:
    """Accept both 'go run ./cmd/aerf-verify' and a bare binary path."""
    return shlex.split(spec)
