#!/usr/bin/env bash
# Render the canonical example into a single-file HTML report.
# Output goes to scripts/test-outputs/example.html.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
OUT_DIR="$HERE/test-outputs"
mkdir -p "$OUT_DIR"

cd "$ROOT"
go run ./cmd/aerf-render \
  --title "AERF claims-agent receipt" \
  --output "$OUT_DIR/example.html" \
  example/receipt.json example/public_key.pem

echo "wrote $OUT_DIR/example.html"
