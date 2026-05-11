#!/usr/bin/env python3
"""Validate every receipt under vectors/ against the appropriate schema.

A receipt that carries any v0.2 fields (parent_signature, pdp_signature,
context_hash_sha256, log_inclusion_proof, impact_tags) is validated
against schemas/aerf-v0.2.json. Otherwise it falls back to
schemas/aerf-v0.1.json so v0.1-shaped receipts remain checkable.

Vectors marked KNOWN_LIMIT may carry deliberately-shaped receipts that
are valid under the schema but documented as residual at the verifier
layer; they are still expected to validate.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from jsonschema import Draft202012Validator


REPO_ROOT = Path(__file__).resolve().parent.parent
SCHEMAS = REPO_ROOT / "schemas"
VECTORS = REPO_ROOT / "vectors"

V02_TRIGGER_FIELDS = (
    "parent_signature",
    "parent_key_id",
    "pdp_signature",
    "pdp_key_id",
    "context_hash_sha256",
    "log_inclusion_proof",
    "impact_tags",
)


def load_schema(path: Path) -> dict:
    return json.loads(path.read_text())


def pick_schema(receipt: dict, v01: dict, v02: dict) -> tuple[str, dict]:
    if any(k in receipt for k in V02_TRIGGER_FIELDS):
        return "v0.2", v02
    return "v0.1", v01


def iter_receipts(root: Path):
    """Yield (receipt_path, expected_outcome) tuples."""
    for vec_dir in sorted(p for p in root.iterdir() if p.is_dir()):
        expected_file = vec_dir / "expected.json"
        outcome = "PASS"
        if expected_file.exists():
            outcome = json.loads(expected_file.read_text()).get("outcome", "PASS")
        single = vec_dir / "receipt.json"
        if single.exists():
            yield single, outcome
        rdir = vec_dir / "receipts"
        if rdir.exists():
            for r in sorted(rdir.glob("*.json")):
                yield r, outcome


def main() -> int:
    v01 = load_schema(SCHEMAS / "aerf-v0.1.json")
    v02 = load_schema(SCHEMAS / "aerf-v0.2.json")
    validator_v01 = Draft202012Validator(v01)
    validator_v02 = Draft202012Validator(v02)

    failures = 0
    total = 0
    for receipt_path, expected in iter_receipts(VECTORS):
        total += 1
        receipt = json.loads(receipt_path.read_text())
        which, _ = pick_schema(receipt, v01, v02)
        validator = validator_v02 if which == "v0.2" else validator_v01
        errors = sorted(validator.iter_errors(receipt), key=lambda e: e.path)
        rel = receipt_path.relative_to(REPO_ROOT)

        if errors:
            # Receipts whose vector outcome is FAIL are intentionally
            # malformed (they exercise verifier rejection paths). A
            # schema rejection is informational; consistent with the
            # verifier rejecting at runtime.
            if expected == "FAIL":
                print(f"info {rel} (schema {which}) intentionally invalid — expected={expected}")
            else:
                failures += 1
                print(f"FAIL {rel} (schema {which})")
                for err in errors:
                    pointer = "/".join(str(p) for p in err.absolute_path)
                    print(f"  - {pointer or '<root>'}: {err.message}")
        else:
            print(f"ok   {rel} (schema {which})")

    print()
    print(f"{total - failures}/{total} receipts pass schema validation")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
