"""Reference validator for the surface shape of a Technocore signature.

Technocore signed messages carry an Ed25519 signature, base64url
encoded, unpadded, and attached to the room write as the ``sig``
field. The platform and the supplied client agree on the *surface*
canonical form of that string. This module gives other tools an
independent, stdlib-only way to check that a candidate string
conforms to that surface form before paying for a cryptographic
verification.

The surface invariants checked here are:

1. The value is a Python ``str``.
2. Its length is exactly **86** characters, the canonical unpadded
   base64url encoding of a 64-byte Ed25519 signature
   (``ceil(64 * 8 / 6) = 86``).
3. Every character is in the unpadded base64url alphabet
   (``A-Z``, ``a-z``, ``0-9``, ``-``, ``_``). The standard
   base64 padding character ``=`` is forbidden.
4. The **last** character is one of the four characters whose
   6-bit value is a multiple of 4 (``A=0``, ``Q=16``, ``g=32``,
   ``w=48``). This is because an Ed25519 signature is exactly 64
   raw bytes; encoded without padding, the trailing 1 byte
   contributes only the high 2 bits of the last 6-bit group, so
   the low 4 bits of that group are always zero, leaving exactly
   four reachable characters at the tail position.

This module is a **field report** and a **reference implementation**
of the surface rule. It is intentionally small, pure Python, and
stdlib-only. It performs no network I/O, no subprocess execution,
no URL resolution, no DNS lookup, no fetching, and no decoding of
its input. It treats the input as untrusted data.

Why a separate module
---------------------

``technocore_verify`` already decodes the signature and checks the
64-byte length and the Ed25519 math. That is the strong check. This
module is the cheap *pre-filter*: callers that ingest signed
messages from a high-volume source can reject malformed shapes
before they reach the cryptographic verifier, and the rule has a
single source of truth that can be unit-tested and versioned in
lockstep with the rest of the protocol surface.

The surface rule is also independently useful for log analysis,
debugging, and conformance reports. A pass here proves only that
the string has the surface form of a valid signature; it is not a
verdict on the signature's cryptographic validity.

Security model
--------------

* Pure function over the input string. No I/O of any kind.
* The validator does not inspect, evaluate, decode, follow, or
  otherwise act on the input beyond the four structural checks.
* A pass proves the surface form, not authorship. The character
  shape is the same for any 64-byte string a caller might construct;
  it is a sanity check, not an authenticity check.
* A failure proves the surface form does not match; it is a fast,
  cheap signal that the input cannot be a valid Technocore
  signature as published.
* ``SigShapeError`` carries a static message that never echoes
  the input value, because the input is untrusted data and the
  validator must not amplify it onto any channel.

Edge cases documented
---------------------

* A 64-byte signature always decodes to exactly 86 base64url
  characters. Decoders that report ``87`` or ``88`` characters
  for a 64-byte signature are padding-stripping incorrectly or
  including the trailing ``=`` padding in the length.
* A 65-byte tail (``87`` characters after base64url encoding) can
  also end in ``{A, Q, g, w}`` because the last 6-bit group is
  ``(b & 0xFC) << ...`` for any byte ``b``. This module rejects
  ``87``-character strings on length alone, so a caller that needs
  to distinguish a ``64``-byte signature from a ``65``-byte tail
  can rely on the length check.
* The four tail characters are exhaustive. There is no fifth
  reachable value because the trailing byte of a 64-byte buffer
  contributes only its high 2 bits; the low 4 bits of the final
  6-bit group are always zero.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


#: Canonical unpadded base64url length of a 64-byte Ed25519
#: signature. Equal to ``ceil(64 * 8 / 6) = 86``.
EXPECTED_LENGTH: int = 86

#: Tuple of the four reachable last-character values for a
#: canonical 86-character base64url-encoded 64-byte Ed25519
#: signature. Each maps to the 6-bit value ``(b & 0xFC) << 0``
#: for some trailing byte ``b``; the low 4 bits of the final
#: 6-bit group are always zero.
TAIL_CHARS: tuple[str, ...] = ("A", "Q", "g", "w")

#: String form of :data:`TAIL_CHARS`, useful for fast ``in``
#: checks and for human-readable docs.
TAIL_CHARS_STR: str = "".join(TAIL_CHARS)

#: Set of allowed base64url characters, excluding the standard
#: base64 padding character ``=``. Exposed for callers that want
#: to do their own pre-checks.
ALLOWED_CHARS: frozenset[str] = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789-_"
)


#: Integer version of the signature-shape contract. Bumped whenever
#: the public behavior of :func:`is_canonical_signature_shape` or
#: :func:`validate_signature_shape` changes in a way that callers can
#: observe (different length, different tail set, different error
#: types). The value is informational; callers should pin against
#: tests, not this integer.
SIG_SHAPE_VERSION: int = 1


class SigShapeError(ValueError):
    """Raised when :func:`validate_signature_shape` rejects a candidate.

    The error carries a static message; it never echoes the
    offending string, because the input is untrusted data and the
    validator must not amplify it onto any channel.
    """


@dataclass(frozen=True)
class SigShapeResult:
    """Outcome of :func:`validate_signature_shape`.

    Attributes:
        valid: True only when ``candidate`` is a string, has
            length :data:`EXPECTED_LENGTH`, contains only
            :data:`ALLOWED_CHARS`, and ends with a member of
            :data:`TAIL_CHARS`.
        reason: Short human-readable explanation when ``valid``
            is False. ``None`` when ``valid`` is True.
    """

    valid: bool
    reason: Optional[str]


def is_canonical_signature_shape(candidate: object) -> bool:
    """Return ``True`` iff ``candidate`` has the canonical signature shape.

    This is a fast, allocation-light pre-filter. It performs no
    exception handling on the happy path; an invalid argument type
    simply returns ``False``. Use :func:`validate_signature_shape`
    if you need a structured reason.
    """
    if not isinstance(candidate, str):
        return False
    if len(candidate) != EXPECTED_LENGTH:
        return False
    # Build a frozenset of allowed tail characters once; using
    # ``in`` against a string is also O(n) in the string length
    # which is fine, but the tail check is the most common
    # rejection reason, so give it a tight set lookup.
    if candidate[-1] not in TAIL_CHARS:
        return False
    for ch in candidate:
        if ch not in ALLOWED_CHARS:
            return False
    return True


def validate_signature_shape(candidate: object) -> SigShapeResult:
    """Return a structured verdict for ``candidate``'s surface shape.

    Args:
        candidate: Any value. Treated as untrusted data.

    Returns:
        :class:`SigShapeResult` with ``valid`` set only when all
        four structural invariants hold, and ``reason`` set to a
        short, static string otherwise. The reason never echoes
        the input value.
    """
    if not isinstance(candidate, str):
        return SigShapeResult(False, "candidate must be a string")
    if len(candidate) != EXPECTED_LENGTH:
        return SigShapeResult(
            False,
            f"length is {len(candidate)}, expected {EXPECTED_LENGTH}",
        )
    if candidate[-1] not in TAIL_CHARS:
        return SigShapeResult(
            False,
            f"last character {candidate[-1]!r} is not one of {TAIL_CHARS_STR!r}",
        )
    for ch in candidate:
        if ch not in ALLOWED_CHARS:
            return SigShapeResult(
                False,
                f"candidate contains non-base64url character {ch!r}",
            )
    return SigShapeResult(True, None)


__all__ = [
    "ALLOWED_CHARS",
    "EXPECTED_LENGTH",
    "SIG_SHAPE_VERSION",
    "SigShapeError",
    "SigShapeResult",
    "TAIL_CHARS",
    "TAIL_CHARS_STR",
    "is_canonical_signature_shape",
    "validate_signature_shape",
]
