# aerf-adversary

A small Python pen-testing library for AERF v0.2 verifiers. Generates
malicious receipts and runs them against any verifier via subprocess.

The library validates the AERF v0.2 Go reference verifier today and is
designed to run unchanged against the upcoming Python verifier or any
third-party verifier.

## Install

```bash
cd tools/aerf-adversary
pip install -e .
```

Requires Python 3.11+ and the `cryptography` package.

## Run

```bash
# Run every attack against the reference verifier.
aerf-adversary --verifier "$(pwd)/../../build/aerf-verify"

# Run a single attack with detail.
aerf-adversary --attack split_context --verbose

# List the catalog.
aerf-adversary --list

# Write a JSON report instead of console output.
aerf-adversary --verifier path/to/aerf-verify --output report.json
```

## Catalog

| Attack | Expected | What it does |
|--------|----------|--------------|
| `signature_forgery` | REJECT | Signs the canonical payload with a different keypair. |
| `receipt_tamper` | REJECT | Mutates a field after signing. |
| `chain_manipulation` | REJECT | Breaks `previous_receipt_hash` chain integrity. |
| `replay` | ACCEPT | Replays a valid receipt; EVIDENCE profile has no replay token. |
| `compromised_child` | REJECT | The C-12 base case: agent signs a false HIGH-IMPACT claim. |
| `split_context` | REJECT | PDP signed verdict for context A; receipt claims context B. |
| `tag_stripping` | KNOWN_LIMIT | Strips `impact_tags`; verifier cannot detect (SPEC §12.7). |
| `log_spoofing` | REJECT | Forged STH signature on log inclusion proof. |
| `canonicalization_tricks` | REJECT | Duplicate keys, type confusion. |
| `common_mode` | KNOWN_LIMIT | All signers honest, upstream context poisoned (SPEC §12.6). |
| `mmd_violation` | REJECT | Async parent counter-sign missing for delegated action. |

`KNOWN_LIMIT` attacks are documented residuals; the verifier accepts
the receipt and the harness reports the outcome as expected.

## Output

Each attack produces an `AttackResult` with the threat model attribution
(which entity is compromised), the expected and actual verifier
outcomes, stderr from the verifier, and the on-disk path to the
generated artifact for forensic review.
