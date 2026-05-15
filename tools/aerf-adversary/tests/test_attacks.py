"""Run every attack against the AERF_VERIFIER binary and assert each
matches its expected outcome.

The test is intentionally lightweight; it exists so the package self-
tests in CI. Heavy validation lives in tools/run-vectors.py.
"""

from __future__ import annotations

import os
import shutil
import tempfile
import unittest
from pathlib import Path

from aerf_adversary.attacks import ALL_ATTACKS
from aerf_adversary.runner import AttackContext, parse_verifier, run_against_verifier


def _resolve_verifier() -> str:
    env = os.environ.get("AERF_VERIFIER")
    if env:
        return env
    candidate = shutil.which("aerf-verify")
    if candidate:
        return candidate
    raise unittest.SkipTest("AERF_VERIFIER not set and aerf-verify not on PATH")


class AdversaryTest(unittest.TestCase):
    def test_each_attack_matches_expected(self) -> None:
        verifier_spec = _resolve_verifier()
        verifier_cmd = parse_verifier(verifier_spec)
        with tempfile.TemporaryDirectory(prefix="aerf-adversary-tests-") as tmp:
            ctx = AttackContext(workdir=Path(tmp))
            for cls in ALL_ATTACKS:
                with self.subTest(attack=cls.name):
                    attack = cls()
                    result = run_against_verifier(verifier_cmd, attack, ctx)
                    self.assertTrue(
                        result.matches_expected,
                        msg=(
                            f"attack={cls.name} expected={result.expected} "
                            f"actual={result.actual} stderr={result.stderr!r}"
                        ),
                    )


if __name__ == "__main__":
    unittest.main()
