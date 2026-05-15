"""Command-line entry point for the adversary suite."""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path

from .attacks import ALL_ATTACKS, get
from .runner import AttackContext, parse_verifier, run_against_verifier


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="AERF v0.2 pen-testing harness.")
    parser.add_argument("--verifier", default="",
                        help="verifier command (binary path or 'go run ...')")
    parser.add_argument("--attack", default="",
                        help="run a single attack by name")
    parser.add_argument("--list", action="store_true",
                        help="list available attacks and exit")
    parser.add_argument("--workdir", default="",
                        help="reuse a fixed workdir instead of a tempdir")
    parser.add_argument("--output", default="",
                        help="write the full report as JSON to this path")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args(argv)

    if args.list:
        for cls in ALL_ATTACKS:
            print(f"{cls.name:<28} {cls.expected_outcome:<11} {cls.description}")
        return 0

    if not args.verifier:
        parser.error("--verifier is required (unless --list)")

    verifier_cmd = parse_verifier(args.verifier)
    catalog = [get(args.attack)] if args.attack else ALL_ATTACKS

    if args.workdir:
        workdir = Path(args.workdir)
        ctx = AttackContext(workdir=workdir)
        return _run(ctx, catalog, verifier_cmd, args)
    with tempfile.TemporaryDirectory(prefix="aerf-adversary-") as tmp:
        ctx = AttackContext(workdir=Path(tmp))
        return _run(ctx, catalog, verifier_cmd, args)


def _run(ctx, catalog, verifier_cmd, args) -> int:
    results = []
    failures = 0
    for cls in catalog:
        attack = cls()
        r = run_against_verifier(verifier_cmd, attack, ctx)
        results.append(r)
        marker = " " if r.matches_expected else "!"
        print(f"{marker} {r.name:<28} expected={r.expected:<12} actual={r.actual:<6} "
              f"{'MATCH' if r.matches_expected else 'MISMATCH'}")
        if args.verbose:
            print(f"      threat: {r.threat_model}")
            print(f"      artifact: {r.artifact_path}")
            if r.stderr.strip():
                for line in r.stderr.strip().splitlines():
                    print(f"      stderr: {line}")
        if not r.matches_expected:
            failures += 1

    print()
    print(f"{len(results) - failures}/{len(results)} attacks matched expectations")

    if args.output:
        Path(args.output).write_text(
            json.dumps([r.to_dict() for r in results], indent=2)
        )
        print(f"report written to {args.output}")

    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
