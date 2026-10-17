"""Canonical single-pass text sweep for the Technocore protocol.

This module is the public, reference implementation of the
``sweep`` step that Technocore applies to room message ``text``
before storing and signing. The full protocol note is in
``docs/protocol-notes.md``; in short:

* Characters in the four ranges below are replaced, in a single
  left-to-right pass, with U+0020 (space).
* All other codepoints (including CJK, emoji, NBSP, ligatures, and
  zero-width joiners outside the documented ranges) are preserved
  byte-for-byte.
* The replacement is exactly one U+0020 per replaced codepoint; no
  collapsing, no trimming, no normalization of the surrounding text.

Why a separate module
---------------------

``technocore_verify.sweep`` has always been the place this rule lived,
because the verifier has to apply the sweep to reconstruct the
canonical bytes that were signed. As the rule set gets referenced by
more tools (offline signers, debugging harnesses, conformance
checkers, third-party SDKs), the sweep itself needs to be importable
on its own — and it needs an obvious single source of truth so that
the verifier and the signer cannot drift.

This module is that single source of truth. ``technocore_verify``
imports ``sweep`` from here; future tools should do the same.

Security model
--------------

* The sweep is a pure function. It performs no network I/O, no
  filesystem I/O beyond the input string, no subprocess execution,
  no URL resolution, no DNS lookup, no fetching, and no decoding of
  the input.
* The sweep treats the input as untrusted data. It is safe to call
  on arbitrary participant-supplied text.
* ``SweepReport`` exposes a *count* and a *set of codepoints* that
  were replaced, not the full text. Callers that need to log the
  replaced content must do so on a trusted channel with the
  original input they supplied.

Scope
-----

* In scope: the four documented sweep ranges, length accounting,
  replaced-codepoint reporting, strict input validation.
* Out of scope: NFC/NFKC normalization, case folding, locale-aware
  whitespace handling, bidi reordering, URL/path/shell/credential
  detection (see ``technocore_scanner``), signature verification
  (see ``technocore_verify``).
"""
from __future__ import annotations

import dataclasses
from typing import FrozenSet, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Protocol constants
# ---------------------------------------------------------------------------

#: Codepoint ranges replaced with U+0020 (space) by the single-pass sweep.
#: Mirrors the supplied Hermes client and ``docs/protocol-notes.md``.
#: Each tuple is an inclusive lower bound and an exclusive upper bound.
SWEEP_RANGES: Tuple[Tuple[int, int], ...] = (
    (0x0000, 0x0020),  # C0 controls (plus the NUL through unit-separator range)
    (0x007F, 0x00A0),  # DEL + C1 controls
    (0x200B, 0x2010),  # zero-width space, ZWNJ, ZWJ, LRM, RLM, ...
    (0x202A, 0x202F),  # bidirectional embedding / isolate / override controls
)

#: Codepoint used as the replacement for every matched character.
SWEEP_REPLACEMENT: str = " "


class SweepError(ValueError):
    """Raised when ``sweep`` is given an invalid input."""


# ---------------------------------------------------------------------------
# Public dataclass
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class SweepReport:
    """Outcome of sweeping a single input.

    Attributes:
        original: The input text, exactly as supplied.
        swept: The post-sweep text. Always a ``str``. Equal to
            ``sweep(original)``.
        replaced_count: Number of codepoints in ``original`` that fell
            inside ``SWEEP_RANGES`` and were replaced with U+0020.
        replaced_codepoints: Distinct codepoints that were replaced,
            each as a single-character string. The set is empty when
            ``replaced_count`` is zero.
        length_delta: ``len(swept) - len(original)``. Always zero
            because the sweep is a 1:1 character substitution; the
            field is exposed for callers that want a sanity check
            and to make the dataclass self-describing.

    Note:
        ``replaced_count`` and ``replaced_codepoints`` describe what
        the sweep *did* to the input. They are not a verdict on
        whether the input was safe, well-formed, or in any other
        way acceptable to the network.
    """

    original: str
    swept: str
    replaced_count: int
    replaced_codepoints: FrozenSet[str]
    length_delta: int


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _in_ranges(ord_value: int) -> bool:
    """Return ``True`` iff ``ord_value`` falls inside any sweep range."""
    # Linear scan is fine: the ranges are tiny (4 tuples) and this
    # is the inner loop of a per-character hot path. A precomputed
    # frozenset would obscure the rule without measurably speeding
    # things up at typical message sizes.
    for lo, hi in SWEEP_RANGES:
        if lo <= ord_value < hi:
            return True
    return False


def _check_input(text: object) -> None:
    """Raise ``SweepError`` unless ``text`` is a string."""
    if not isinstance(text, str):
        raise SweepError("text must be a str")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def sweep(text: str) -> str:
    """Apply the protocol's single-pass control-character sweep.

    The replacement is always U+0020 (space). No other transformation
    is performed. The function is deterministic and idempotent:
    ``sweep(sweep(x)) == sweep(x)``.

    Args:
        text: Any string. Must be a ``str``; bytes-like and other
            types raise ``SweepError``.

    Returns:
        A new ``str`` of the same length as ``text`` with the
        documented codepoint ranges replaced by U+0020.

    Raises:
        SweepError: If ``text`` is not a ``str``.
    """
    _check_input(text)
    if not text:
        return ""

    out: List[str] = []
    append = out.append
    for ch in text:
        if _in_ranges(ord(ch)):
            append(SWEEP_REPLACEMENT)
        else:
            append(ch)
    return "".join(out)


def sweep_report(text: str) -> SweepReport:
    """Run :func:`sweep` and report which codepoints were replaced.

    This is a convenience wrapper that returns the same string as
    :func:`sweep` plus a structured description of the changes. It
    is useful for debugging signature mismatches, conformance
    testing, and logging on a trusted channel.

    Args:
        text: Any string.

    Returns:
        A :class:`SweepReport` with the post-sweep string and a
        count + set of replaced codepoints.

    Raises:
        SweepError: If ``text`` is not a ``str``.
    """
    _check_input(text)
    if not text:
        return SweepReport(
            original="",
            swept="",
            replaced_count=0,
            replaced_codepoints=frozenset(),
            length_delta=0,
        )

    out: List[str] = []
    replaced: List[str] = []
    seen: set = set()
    append_out = out.append
    append_repl = replaced.append
    add_seen = seen.add
    for ch in text:
        if _in_ranges(ord(ch)):
            append_out(SWEEP_REPLACEMENT)
            append_repl(ch)
            add_seen(ch)
        else:
            append_out(ch)
    swept = "".join(out)
    return SweepReport(
        original=text,
        swept=swept,
        replaced_count=len(replaced),
        replaced_codepoints=frozenset(seen),
        length_delta=len(swept) - len(text),
    )


def expected_replacements(
    text: str,
) -> Optional[Tuple[int, FrozenSet[str]]]:
    """Return ``(replaced_count, distinct_codepoints)`` without building the swept string.

    Useful when the caller only needs the *count* and *set* of
    replaced codepoints (for example, to gate a side effect) and
    wants to avoid the cost of constructing the post-sweep string.

    Args:
        text: Any string.

    Returns:
        A 2-tuple ``(count, frozenset_of_codepoints)`` when
        ``text`` is a string. ``count`` is the number of matched
        codepoints; the frozenset lists each distinct matched
        codepoint as a single-character string.

    Raises:
        SweepError: If ``text`` is not a ``str``.
    """
    _check_input(text)
    if not text:
        return 0, frozenset()
    count = 0
    seen: set = set()
    add_seen = seen.add
    for ch in text:
        if _in_ranges(ord(ch)):
            count += 1
            add_seen(ch)
    return count, frozenset(seen)


__all__ = [
    "SweepError",
    "SweepReport",
    "SWEEP_RANGES",
    "SWEEP_REPLACEMENT",
    "expected_replacements",
    "sweep",
    "sweep_report",
]
