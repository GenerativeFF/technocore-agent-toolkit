"""Nonce and replay checker for the Technocore protocol.

This module provides functions to validate nonces against protocol rules
and to detect replay attacks by tracking seen nonces.

It also exposes a stateless ``nonce_safety_assessment`` companion that
adds two implementation-side checks callers can opt into:

* a float-precision check (does the integer value fit exactly in an
  IEEE 754 double, so a non-Python caller does not silently round-trip
  the nonce through ``float`` and lose precision above ``2**53``);
* an entropy check (is the bit length of the integer value large
  enough to make a brute-force search of the (room, nonce, text)
  space infeasible for an attacker who is replaying observed
  signatures).

The shape and ordering rules come from
``docs/protocol-notes.md`` and are unchanged here.
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


# --- Nonce safety assessment (v1.0.2) -----------------------------------
#
# Pure-function companion to ``NonceChecker.check_and_update``. Same shape
# validation, plus two implementation-side flags callers can use to
# harden their own pipeline without coupling to the network.
#
# IEEE 754 double precision uses a 53-bit mantissa, so integers up to
# ``2**53 - 1 = 9_007_199_254_740_991`` are exactly representable. Any
# larger integer loses precision when round-tripped through ``float``,
# which is a common bug in non-Python clients that decode JSON numbers
# as ``double`` by default. The Technocore nonce spec allows up to 19
# decimal digits (max ``9_999_999_999_999_999_999``), so this is a real
# risk for callers on JavaScript, Java, or other float-default
# platforms.
#
# The bit-length check is a defense-in-depth control against
# brute-force search: a nonce with fewer than ``DEFAULT_MIN_BITS`` bits
# gives an attacker at most ``2**bit_length`` distinct (room, nonce)
# pairs to try, which is feasible on commodity hardware well below the
# protocol's 19-digit cap.

#: The largest integer exactly representable in an IEEE 754 double.
FLOAT53_MAX_EXACT: int = (1 << 53) - 1  # 9_007_199_254_740_991

#: The number of significant bits in an IEEE 754 double mantissa.
FLOAT53_BITS: int = 53

#: Default minimum bit length the safety check uses to flag a "low
#: entropy" nonce. ``2**32`` is roughly 4.3 billion distinct values,
#: which is at the lower edge of what a determined offline attacker
#: can enumerate; callers that want stricter or looser behavior can
#: pass their own value to ``nonce_safety_assessment``.
DEFAULT_MIN_BITS: int = 32

#: Contract version for the safety assessment API.
NONCE_SAFETY_VERSION: int = 1


@dataclasses.dataclass(frozen=True)
class NonceSafetyResult:
    """Structured verdict for ``nonce_safety_assessment``.

    Attributes:
        valid: True if the nonce is a well-formed positive integer
            that fits the documented shape (1..19 decimal digits).
        reason: Static, parameter-free explanation when ``valid`` is
            False. Never echoes the input value.
        fits_in_float53: True if the integer value is exactly
            representable in an IEEE 754 double (``<= 2**53 - 1``).
            Only meaningful when ``valid`` is True.
        bit_length: Number of significant bits in the integer value
            (e.g. ``1`` for ``"1"``, ``10`` for ``"1024"``). Only
            meaningful when ``valid`` is True.
        entropy_warning: True if ``bit_length`` is below the requested
            ``min_bits`` threshold. Only meaningful when ``valid`` is
            True. ``valid`` is still True when this is True; the
            warning is informational and the protocol permits the
            nonce.
        version: Contract version of the safety assessment API.
    """
    valid: bool
    reason: Optional[str] = None
    fits_in_float53: bool = True
    bit_length: int = 0
    entropy_warning: bool = False
    version: int = NONCE_SAFETY_VERSION


def nonce_safety_assessment(
    nonce_str: str,
    *,
    min_bits: int = DEFAULT_MIN_BITS,
) -> NonceSafetyResult:
    """Return a structured safety verdict for a nonce string.

    This is a pure function with no state, no network I/O, and no
    dependency on ``NonceChecker``. The shape validation matches
    ``NonceChecker.check_and_update``:

    * 1..19 decimal digits;
    * positive integer (``"0"`` is rejected, matching the protocol
      rule that nonces must be strictly increasing for the key).

    When the nonce is well-formed, the verdict additionally reports:

    * ``bit_length`` — the bit length of the integer value;
    * ``fits_in_float53`` — whether the integer fits exactly in an
      IEEE 754 double (``<= 2**53 - 1``);
    * ``entropy_warning`` — whether the bit length is below
      ``min_bits`` (default 32). The warning is informational; the
      nonce is still considered ``valid`` for protocol purposes.

    The function does not check ordering or replay; that is the job
    of ``NonceChecker.check_and_update`` and its per-``(did, room)``
    state. Callers that want both shape and ordering should use
    ``NonceChecker``; callers that want to *also* surface a float or
    entropy warning to their own UI or logs should call this
    function first (or in parallel) and use the structured fields.

    Args:
        nonce_str: The nonce as it appears on the wire, a decimal
            string. Treated as untrusted data; never echoed.
        min_bits: Bit-length threshold below which a
            ``entropy_warning`` is raised. Must be a positive
            integer. Defaults to ``DEFAULT_MIN_BITS`` (32).

    Returns:
        A ``NonceSafetyResult`` with ``valid``, the structured
        reasons, and the contract ``version``.

    Raises:
        TypeError: If ``nonce_str`` is not a ``str``, or ``min_bits``
            is not an ``int``.
        ValueError: If ``min_bits`` is not positive.
    """
    if not isinstance(nonce_str, str):
        raise TypeError("nonce_str must be a str")
    if not isinstance(min_bits, int) or isinstance(min_bits, bool):
        raise TypeError("min_bits must be a positive int")
    if min_bits <= 0:
        raise ValueError("min_bits must be a positive int")

    if not (1 <= len(nonce_str) <= 19) or not nonce_str.isdigit():
        return NonceSafetyResult(
            valid=False,
            reason="nonce must be 1..19 decimal digits",
        )

    # ``str.isdigit()`` accepts decimal digits plus a few non-ASCII
    # digit code points; the protocol is 1..19 *decimal* digits, so
    # restrict to ASCII 0-9 explicitly. ``str.isdigit()`` also
    # rejects the empty string, so the length check above is the
    # primary guard; this is defense in depth.
    if not all("0" <= ch <= "9" for ch in nonce_str):
        return NonceSafetyResult(
            valid=False,
            reason="nonce must be 1..19 decimal digits",
        )

    # ``int()`` on a verified digit string cannot raise; the
    # ``ValueError`` branch is for callers that bypass the check.
    try:
        nonce = int(nonce_str)
    except ValueError:
        return NonceSafetyResult(
            valid=False,
            reason="nonce must be a valid integer",
        )

    if nonce <= 0:
        return NonceSafetyResult(
            valid=False,
            reason="nonce must be positive",
        )

    bit_length = nonce.bit_length()
    fits_in_float53 = nonce <= FLOAT53_MAX_EXACT
    entropy_warning = bit_length < min_bits

    return NonceSafetyResult(
        valid=True,
        fits_in_float53=fits_in_float53,
        bit_length=bit_length,
        entropy_warning=entropy_warning,
    )


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
    "DEFAULT_MIN_BITS",
    "FLOAT53_BITS",
    "FLOAT53_MAX_EXACT",
    "NONCE_SAFETY_VERSION",
    "NonceError",
    "NonceCheckResult",
    "NonceChecker",
    "NonceSafetyResult",
    "nonce_safety_assessment",
]
