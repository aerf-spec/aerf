"""Catalog of AERF v0.2 attacks."""

from .base import Attack, ReceiptArtifact
from .signature_forgery import SignatureForgery
from .receipt_tamper import ReceiptTamper
from .chain_manipulation import ChainManipulation
from .replay import Replay
from .compromised_child import CompromisedChild
from .split_context import SplitContext
from .tag_stripping import TagStripping
from .log_spoofing import LogSpoofing
from .canonicalization_tricks import CanonicalizationTricks
from .common_mode import CommonMode
from .mmd_violation import MMDViolation


ALL_ATTACKS: list[type[Attack]] = [
    SignatureForgery,
    ReceiptTamper,
    ChainManipulation,
    Replay,
    CompromisedChild,
    SplitContext,
    TagStripping,
    LogSpoofing,
    CanonicalizationTricks,
    CommonMode,
    MMDViolation,
]


def get(name: str) -> type[Attack]:
    for cls in ALL_ATTACKS:
        if cls.name == name:
            return cls
    raise KeyError(f"unknown attack: {name}")


__all__ = ["Attack", "ReceiptArtifact", "ALL_ATTACKS", "get"]
