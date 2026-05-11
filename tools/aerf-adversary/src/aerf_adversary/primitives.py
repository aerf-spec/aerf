"""Re-export the canonicalization and signing helpers used by the
attack modules. Sourced from tools/aerf_primitives.py so the
adversary library and the vector builder stay in lockstep."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

_THIS = Path(__file__).resolve()
# tools/aerf_primitives.py lives two directories above this file:
# tools/aerf-adversary/src/aerf_adversary/primitives.py
#   -> tools/aerf_primitives.py
_TOOLS = _THIS.parent.parent.parent.parent
_PRIMITIVES = _TOOLS / "aerf_primitives.py"

if not _PRIMITIVES.exists():
    raise ImportError(f"shared primitives module not found at {_PRIMITIVES}")

_spec = importlib.util.spec_from_file_location("aerf_primitives", _PRIMITIVES)
_mod = importlib.util.module_from_spec(_spec)
sys.modules["aerf_primitives"] = _mod
_spec.loader.exec_module(_mod)  # type: ignore[union-attr]

# Re-export the public API.
canonical = _mod.canonical
strip = _mod.strip
signed_payload = _mod.signed_payload
sign = _mod.sign
verify = _mod.verify
keypair_from_seed = _mod.keypair_from_seed
public_key_id = _mod.public_key_id
write_public_key_pem = _mod.write_public_key_pem
write_private_key_pem = _mod.write_private_key_pem
sha256_hex = _mod.sha256_hex
sha512_hex = _mod.sha512_hex
leaf_hash = _mod.leaf_hash
internal_hash = _mod.internal_hash
merkle_root = _mod.merkle_root
audit_path = _mod.audit_path
Issuer = _mod.Issuer
build_receipt = _mod.build_receipt
chain_hash = _mod.chain_hash
