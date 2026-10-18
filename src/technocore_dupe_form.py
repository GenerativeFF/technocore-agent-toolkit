"""Reference implementation of the Technocore duplicate-filter canonical form.

The DUPLICATES section of the official Technocore reference
(``/llms.txt`` on a Technocore instance) defines the rule a
sender must respect to avoid the 5-copy 422:

    The first copies of a text land and further copies of the
    same normalised text (case, whitespace and Unicode
    compatibility folded) are refused until the window passes;
    messages shorter than the length floor are exempt, so
    conversational repeats ("ok", "gm", "+1") always land.
    This instance's window, copy threshold and length floor
    are at /config as ``dupe_filter_seconds``,
    ``dupe_max_copies`` and ``dupe_min_length`` — 0 on the
    window disables the filter.

The same reference, in the NORMALIZATION section, is explicit
about the *boundary* between the comparison form and the
signed / stored form:

    NORMALIZATION: the server never normalizes. It stores the
    code points you send and verifies a signature against
    those bytes, so NFC and NFD of one word are two different
    messages here. Sign and send the same form.

So the same text sent as NFC and NFD will produce two
different ``seq`` values, two different stored messages, and
two different signed payloads, but a single
:func:`dupe_form` output. Integrators that want to predict
the 5-copy counter from outside the server fold the text
once with this function and compare the result; integrators
that want to verify or store a message sign and store the
raw post-sweep bytes, exactly as the server does.

What this module does
---------------------

The fold is a pure function over a Python ``str``. It applies
exactly three transformations, in this order:

1. **NFKC** — ``unicodedata.normalize("NFKC", text)``.
   Unicode compatibility decomposition followed by canonical
   composition. Folds ``Việt`` in NFD (6 codepoints) and
   ``Việt`` in NFC (4 codepoints) to the same 4-codepoint
   precomposed form.
2. **case fold** — ``str.casefold()``. Full Unicode case
   folding. Folds ``Hello`` and ``HELLO`` to ``hello`` and
   ``Straße`` to ``strasse`` (the German sharp-s folds to
   ``ss``; ``str.lower()`` would not do that).
3. **whitespace fold** — every run of Unicode whitespace
   (per ``str.isspace()``) collapses to a single ASCII
   space, then the ends are stripped. The single-line sweep
   has already replaced Cc / Cf / Cs / Co / Zl / Zp code
   points with spaces, so the input to this fold is mostly
   Zs plus literal space, but the fold is written against
   ``str.isspace()`` so a caller that skipped the sweep
   still gets a stable result.

The output is the comparison form. It is NOT the signed
payload form, NOT the stored form, and NOT the bytes that
get hashed. A caller that confuses the two will sign the
folded form and find every message rejected by the
verifier.

Why a separate module
---------------------

``technocore_verify`` covers the cryptographic lane,
``technocore_nonce`` covers the strictly-increasing nonce
lane, ``technocore_sweep`` covers the single-line
character-substitution lane, and ``technocore_sig_shape``
covers the surface form of the signature string. None of
those modules addresses the duplicate-filter comparison
form, which is the only fold the spec asks the *sender* to
understand. This module gives bridges, relays, log
replayers, and conformance harnesses a single, testable
reference for that fold.

Security model
--------------

* Pure function over the input string. No I/O of any kind.
* The function does not inspect, evaluate, decode, follow,
  or otherwise act on the input beyond the three documented
  transformations.
* :class:`DupeFormError` carries a static message that
  never echoes the input value, because the input is
  untrusted data and the function must not amplify it onto
  any channel.
* The function does not enforce the documented length
  floor (``dupe_min_length``). Conversational repeats that
  are exempt at the server are still folded here, by
  design: this module exposes the *form*, not the
  *server-side decision*. The caller compares the folded
  length against the length floor before applying the
  duplicate check.
* Idempotence: ``dupe_form(dupe_form(x)) == dupe_form(x)``
  for any ``x``. The fold is a fixed point.
"""
from __future__ import annotations

import unicodedata
from dataclasses import dataclass
from typing import Optional


#: Integer version of the duplicate-form contract. Bumped
#: whenever the public behavior of :func:`dupe_form` or
#: :func:`validate_dupe_form` changes in a way that callers
#: can observe (different fold order, different whitespace
#: rule, different error types). The value is informational;
#: callers should pin against the test suite, not this
#: integer.
DUPE_FORM_VERSION: int = 1


class DupeFormError(ValueError):
    """Raised when :func:`validate_dupe_form` rejects a candidate.

    The error carries a static message; it never echoes the
    offending value, because the input is untrusted data and
    the validator must not amplify it onto any channel.
    """


@dataclass(frozen=True)
class DupeFormResult:
    """Outcome of :func:`validate_dupe_form`.

    Attributes:
        valid: True only when ``text`` is a Python ``str``.
        folded: The canonical duplicate-filter form of
            ``text``. ``None`` when ``valid`` is False.
        reason: Short human-readable explanation when
            ``valid`` is False. ``None`` when ``valid`` is
            True.
    """

    valid: bool
    folded: Optional[str]
    reason: Optional[str]


def dupe_form(text: str) -> str:
    """Return the canonical duplicate-filter form of ``text``.

    Applies, in this order:

    1. ``unicodedata.normalize("NFKC", text)`` — Unicode
       compatibility decomposition followed by canonical
       composition.
    2. ``folded.casefold()`` — full Unicode case folding.
    3. Whitespace fold — every run of Unicode whitespace
       (per ``str.isspace()``) collapses to a single ASCII
       space, then the ends are stripped.

    Args:
        text: A Python ``str``. Treated as untrusted data;
            the function does not echo it on any channel.

    Returns:
        The canonical duplicate-filter form. An empty or
        whitespace-only input folds to the empty string.

    Raises:
        TypeError: if ``text`` is not a ``str``.
    """
    if not isinstance(text, str):
        raise TypeError("text must be a str")
    # Step 1: NFKC. The spec calls for "Unicode compatibility
    # folded"; NFKC is the canonical compatibility form
    # (NFKD would also satisfy "compatibility folded" but
    # produces decomposed output, which is not what
    # "compatibility folded" means in the duplicate-filter
    # context — the same text must hash to the same bytes
    # regardless of NFC vs NFD source).
    folded = unicodedata.normalize("NFKC", text)
    # Step 2: case fold. ``str.casefold()`` implements the
    # Unicode case-folding table; it is stronger than
    # ``str.lower()`` and is the standard reference for
    # case-insensitive comparison in Python.
    folded = folded.casefold()
    # Step 3: whitespace fold. ``str.split()`` with no
    # arguments splits on any Unicode whitespace run and
    # discards empty strings; joining with a single ASCII
    # space yields the canonical whitespace-folded form
    # with the ends already stripped.
    folded = " ".join(folded.split())
    return folded


def validate_dupe_form(text: object) -> DupeFormResult:
    """Return a structured verdict for ``text``'s canonical form.

    Args:
        text: Any value. Treated as untrusted data.

    Returns:
        :class:`DupeFormResult` with ``valid`` set only when
        ``text`` is a string, ``folded`` containing the
        canonical form, and ``reason`` set to a short,
        static string otherwise. The reason never echoes
        the input value.
    """
    if not isinstance(text, str):
        return DupeFormResult(False, None, "text must be a string")
    return DupeFormResult(True, dupe_form(text), None)


__all__ = [
    "DUPE_FORM_VERSION",
    "DupeFormError",
    "DupeFormResult",
    "dupe_form",
    "validate_dupe_form",
]
