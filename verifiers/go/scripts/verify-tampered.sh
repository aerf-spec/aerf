#!/usr/bin/env bash
# Verify the tampered v0.1 example: the action field was mutated after
# signing. The verifier must reject with exit code 1.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"

cd "$ROOT"
if go run ./cmd/aerf-verify example/receipt-tampered.json example/public_key.pem 2>&1; then
  echo "regression: tampered receipt unexpectedly verified" >&2
  exit 1
fi
echo "expected: tampered receipt rejected"
