"""Nonce and replay checker for the Technocore protocol.

This module provides functions to validate nonces against protocol rules
and to detect replay attacks by tracking seen nonces.
"""
from __future__ import annotations

import collections
import dataclasses
from typing import Dict, Optional, Tuple


class NonceError(ValueError):
    """Raised for malformed nonces or replay attempts."""


@dataclasses.dataclass(frozen=True)
class NonceCheckResult:
    """Outcome of checking a nonce.

    Attributes:
        valid: True if the nonce is well-formed and not a replay.
        reason: Short human-readable explanation when `valid` is False.
    """
    valid: bool
    reason: Optional[str] = None


class NonceChecker:
    """Manages nonce state for replay protection."""

    def __init__(self):
        # Stores the highest nonce seen per (did, room) pair.
        # Key: (did: str, room: str)
        # Value: int (highest nonce seen)
        self._highest_nonces: Dict[Tuple[str, str], int] = collections.defaultdict(int)

    def check_and_update(self, did: str, room: str, nonce_str: str) -> NonceCheckResult:
        """Checks a nonce for validity and updates the internal state.

        Args:
            did: The DID of the signer.
            room: The room the message was sent in.
            nonce_str: The nonce as a string.

        Returns:
            NonceCheckResult indicating validity and reason if invalid.
        """
        if not (1 <= len(nonce_str) <= 19) or not nonce_str.isdigit():
            return NonceCheckResult(False, "nonce must be 1..19 decimal digits")

        try:
            nonce = int(nonce_str)
        except ValueError:
            return NonceCheckResult(False, "nonce must be a valid integer")

        if nonce <= 0:
            return NonceCheckResult(False, "nonce must be positive")

        key = (did, room)
        highest_seen = self._highest_nonces[key]

        if nonce <= highest_seen:
            return NonceCheckResult(False, f"nonce {nonce} is not strictly greater than highest seen {highest_seen}")

        self._highest_nonces[key] = nonce
        return NonceCheckResult(True)


__all__ = [
    "NonceError",
    "NonceCheckResult",
    "NonceChecker",
]
