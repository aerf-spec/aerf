#!/usr/bin/env bash
# Verify the canonical v0.1 example receipt against the v0.2 reference
# verifier. The example is preserved verbatim across versions to lock
# regression behavior.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"

cd "$ROOT"
go run ./cmd/aerf-verify example/receipt.json example/public_key.pem
