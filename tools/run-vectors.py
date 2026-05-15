#!/usr/bin/env python3
"""Run the AERF conformance vectors against a verifier.

Reads vectors/manifest.json, invokes the verifier on each entry, and
asserts that the actual outcome matches expected.json. A `KNOWN_LIMIT`
outcome is accepted regardless of how the verifier exits, since by
definition the spec acknowledges the gap.

Usage:

    python tools/run-vectors.py \\
        --verifier "go run ./verifiers/go/cmd/aerf-verify" \\
        --vectors vectors/
"""

from __future__ import annotations

import argparse
import json
import shlex
import subprocess
import sys
from pathlib import Path


def discover_inputs(vector_dir: Path) -> list[dict]:
    """Find the receipt(s) and the matching keys + flags in a vector
    directory. Returns a list of {receipt, pubkey, extra_args} dicts,
    one per receipt to verify in order."""
    pubkey = vector_dir / "public_key.pem"
    extra_args: list[str] = []
    if (vector_dir / "parent_key.pem").exists():
        extra_args += ["--parent-key", str(vector_dir / "parent_key.pem")]
    if (vector_dir / "pdp_key.pem").exists():
        extra_args += ["--pdp-key", str(vector_dir / "pdp_key.pem")]
    if (vector_dir / "log_key.pem").exists():
        extra_args += ["--log-key", str(vector_dir / "log_key.pem")]

    receipts_dir = vector_dir / "receipts"
    if receipts_dir.exists():
        return [
            {"receipt": p, "pubkey": pubkey, "extra_args": extra_args}
            for p in sorted(receipts_dir.glob("*.json"))
        ]
    single = vector_dir / "receipt.json"
    if single.exists():
        return [{"receipt": single, "pubkey": pubkey, "extra_args": extra_args}]
    raise FileNotFoundError(f"no receipts found under {vector_dir}")


def run_one(verifier: list[str], inputs: list[dict]) -> tuple[str, str]:
    """Run the verifier on each input in order. Returns (outcome,
    stderr). Outcome is PASS if every receipt exits 0; FAIL on first
    nonzero exit."""
    last_stderr = ""
    for entry in inputs:
        cmd = (
            verifier
            + entry["extra_args"]
            + [str(entry["receipt"]), str(entry["pubkey"])]
        )
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        last_stderr = proc.stderr
        if proc.returncode != 0:
            return "FAIL", last_stderr
    return "PASS", last_stderr


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verifier", required=True,
                        help="verifier command (e.g. 'go run ./verifiers/go/cmd/aerf-verify')")
    parser.add_argument("--vectors", required=True, type=Path)
    args = parser.parse_args()

    verifier_cmd = shlex.split(args.verifier)
    manifest = json.loads((args.vectors / "manifest.json").read_text())

    width = max(len(e["dir"]) for e in manifest)
    failures = 0
    for entry in manifest:
        vec_dir = args.vectors / entry["dir"]
        inputs = discover_inputs(vec_dir)
        actual, stderr = run_one(verifier_cmd, inputs)
        expected = entry["outcome"]
        substr = entry.get("stderr_substring") or ""

        ok = False
        note = ""
        if expected == "KNOWN_LIMIT":
            ok = True
            note = "(known limit: verifier outcome documented as residual)"
        elif expected == actual:
            if expected == "FAIL" and substr and substr not in stderr:
                ok = False
                note = f"(stderr missing {substr!r})"
            else:
                ok = True

        status = "PASS" if ok else "MISMATCH"
        marker = " " if ok else "!"
        print(f"{marker} {entry['dir']:<{width}}  expected={expected:<11}  actual={actual:<6}  {status}  {note}")
        if not ok:
            failures += 1
            if stderr:
                for line in stderr.strip().splitlines():
                    print(f"      stderr: {line}")

    print()
    print(f"{len(manifest) - failures}/{len(manifest)} vectors matched expectations")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
