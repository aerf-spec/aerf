#!/usr/bin/env bash
# Refresh the reference test outputs under scripts/test-outputs/.
# Run this when canonical output text changes; commit the diff.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
OUT="$HERE/test-outputs"
mkdir -p "$OUT"

cd "$ROOT"

go run ./cmd/aerf-verify example/receipt.json example/public_key.pem \
  > "$OUT/verify-example.stdout.txt" 2> "$OUT/verify-example.stderr.txt"
echo "ok: example verify"

set +e
go run ./cmd/aerf-verify example/receipt-tampered.json example/public_key.pem \
  > "$OUT/verify-tampered.stdout.txt" 2> "$OUT/verify-tampered.stderr.txt"
TAMPER_RC=$?
set -e
echo "$TAMPER_RC" > "$OUT/verify-tampered.exit"
echo "ok: tampered verify (exit $TAMPER_RC)"

go run ./cmd/aerf-verify --json example/receipt.json example/public_key.pem \
  > "$OUT/verify-example.json"
echo "ok: example verify --json"

go run ./cmd/aerf-render --title "AERF claims-agent receipt" \
  --output "$OUT/example.html" \
  example/receipt.json example/public_key.pem
echo "ok: example render"
