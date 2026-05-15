# AERF reference verifier — Go

> **Targets AERF v0.2.0-draft.1.** Public review draft, not yet stable.

Two small Go binaries for AERF-EVIDENCE receipts, standard library
only:

- `aerf-verify` — verifies a receipt and prints a one-line result
  or a JSON report.
- `aerf-render` — verifies a receipt and produces a self-contained
  HTML page (no external assets) suitable for embedding in a website
  or serving directly.

Both share a small `internal/aerf` package with the canonicalization,
key handling, and verification logic.

## Layout

```
verifiers/go/
  go.mod
  cmd/
    aerf-verify/      # CLI verifier
    aerf-render/      # HTML report generator
  internal/aerf/      # canonical, key, verify
  example/            # canonical example artifacts
  scripts/            # verification + render walkthrough scripts
    test-outputs/     # reference outputs committed for diffing
```

## What `aerf-verify` checks

- Loads an Ed25519 public key from SPKI PEM (RFC 8410).
- Parses the receipt JSON and re-canonicalizes the payload per
  [SPEC.md §5.1](../../SPEC.md#51-canonical-json) (RFC 8785 JCS).
- Verifies the issuer Ed25519 signature.
- When the relevant flag and key are supplied, additionally verifies
  `parent_signature` (§4.6, §16), `pdp_signature` over the PDP-bound
  tuple (§4.6, §17), and `log_inclusion_proof` against an RFC 9162
  STH (§15).
- Enforces conditional requirements: a receipt whose `impact_tags`
  is non-empty MUST carry `parent_signature` and `pdp_signature` and
  the verifier rejects without them.

What it does **not** do yet: RFC 3161 timestamp verification (§11),
chain verification across multiple receipts (§8).

## Step-by-step walkthrough

The repository ships a small canonical example under `example/`:
a genesis receipt, a tampered copy, and the issuer public key. Both
were produced by the v0.1 reference producer and are preserved
verbatim under v0.2 as a regression vector.

### 1. Build the binaries

```bash
cd verifiers/go
go build ./...
```

### 2. Verify the good example

```bash
go run ./cmd/aerf-verify example/receipt.json example/public_key.pem
```

Expected output:

```
OK  receipt 7473e179
    agent:     claims-agent
    action:    submit:claim:CLM-9920
    in_policy: true
    key_id:    c348d3c785c92249
    parent:    skipped
    pdp:       skipped
    log:       skipped
```

Exit code is `0`.

### 3. Verify the tampered example

```bash
go run ./cmd/aerf-verify example/receipt-tampered.json example/public_key.pem
```

Expected output (on stderr):

```
FAIL issuer_signature issuer signature verification FAILED
```

Exit code is `1`. The tampered file mutates the `action` field after
signing; the signature no longer covers the bytes the verifier sees.

### 4. Render an HTML report for a website

```bash
go run ./cmd/aerf-render \
  --title "AERF claims-agent receipt" \
  --output scripts/test-outputs/example.html \
  example/receipt.json example/public_key.pem
```

`example.html` is a single self-contained file with inlined CSS and
no remote assets. Drop it directly into a static site or open it in
a browser.

### Renderer safety posture

`aerf-render` consumes JSON (the receipt, which may be hostile) and
emits HTML (the report, which may be viewed in a browser). Two
defensive properties:

- All template substitutions go through Go's `html/template`, which
  context-aware escapes by default. Receipt field values rendered
  inside HTML body text are HTML-escaped; values rendered inside HTML
  attributes are attribute-escaped. The template never interpolates
  receipt content into `<script>`, `<style>`, or URL contexts.
- The rendered page contains no external assets: no remote scripts,
  no remote fonts, no remote images. CSS is inlined inside a single
  `<style>` block. Reports therefore work offline and do not leak
  viewer activity to a third party.

The renderer does not validate or sanitize fields beyond what the
template's auto-escaping provides. If a deployment serves rendered
reports to untrusted readers, the operator is responsible for any
further sanitization (for example, a Content Security Policy header)
appropriate to their environment.

The renderer is a v0.2 convenience tool. It is OUT OF SCOPE for the
v0.2 conformance surface: a verifier MUST implement `aerf-verify`
semantics; a renderer is not required.

### 5. Get a machine-readable JSON report

```bash
go run ./cmd/aerf-verify --json example/receipt.json example/public_key.pem
```

The JSON shape mirrors the `Result` struct in `internal/aerf/verify.go`
(`OK`, `IssuerOK`, `ParentOK`, `PDPOK`, `LogOK`, `HasImpact`,
`ImpactTags`, `Warnings`, `FailReason`, `FailCategory`, plus a few
display fields).

### 6. Regenerate reference outputs

Reference outputs live under `scripts/test-outputs/` so reviewers can
diff against committed text. Regenerate them with:

```bash
bash scripts/regenerate-test-outputs.sh
```

## Flags

```
aerf-verify [flags] <receipt.json> <issuer_key.pem>

  --parent-key PEM       verify parent_signature against this key
  --pdp-key PEM          verify pdp_signature against this key
  --log-key PEM          verify log_inclusion_proof against this key
  --require-parent-sig   fail when the parent check cannot run
  --require-pdp-sig      fail when the PDP check cannot run
  --require-log          fail when the log check cannot run
  --json                 emit a JSON report on stdout
```

`aerf-render` takes the same flags plus `--title` and `--output`.

## Exit codes

| Code | Meaning |
|------|---------|
| `0`  | All applicable checks passed. |
| `1`  | A check failed (issuer, parent, PDP, log, chain, timestamp). |
| `2`  | Usage or I/O error (file missing, bad PEM, etc.). |

Diagnostic output on stderr begins with `FAIL <category> <reason>`
so consumers can pattern-match on the category.

## Canonicalization

The verifier emits RFC 8785 JCS canonical bytes. For the ASCII content
in the v0.1 example, the output is byte-identical to Python's
`json.dumps(..., sort_keys=True, separators=(",", ":"),
ensure_ascii=True)`, which is what the v0.1 reference producer used.
v0.2 producers must additionally normalize strings to NFC and encode
numbers inside hashed `context` objects as JSON strings; both are
producer obligations described in SPEC.md §5.1.

## Cross-compilation

```bash
GOOS=linux   GOARCH=amd64 go build -o aerf-verify  ./cmd/aerf-verify
GOOS=darwin  GOARCH=arm64 go build -o aerf-verify  ./cmd/aerf-verify
GOOS=windows GOARCH=amd64 go build -o aerf-verify.exe ./cmd/aerf-verify
```

The same patterns apply to `./cmd/aerf-render`.

## Dependencies

Standard library only. NFC normalization is a producer obligation
under SPEC.md §5.1; the verifier intentionally does not pull in
`golang.org/x/text` so the dependency footprint stays minimal.

## License

Apache 2.0 — see the repository [LICENSE](../../LICENSE).
