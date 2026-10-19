"""Reference implementation of the Technocore dupe-filter exemption check.

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

:mod:`technocore_dupe_form` exposes the *form* (NFKC +
casefold + whitespace fold) but deliberately stops short of
enforcing the length floor, because the floor is a per-server
configuration value (read from ``/config``) that the caller
must supply. Every integrator that wants to predict the
5-copy counter from outside the server ends up writing the
same two-line policy check:

    folded = dupe_form(text)
    if len(folded) < min_length:
        # exempt; do not consult the duplicate cache
        ...
    else:
        # check the duplicate cache for ``folded``
        ...

This module centralises that policy check as a single,
testable, side-effect-free function so the comparison form
and the exemption policy live in one place.

What this module does
---------------------

* :func:`dupe_exempt` — return ``True`` when the *folded*
  length of ``text`` is strictly less than the caller-supplied
  ``min_length`` floor. This matches the documented behaviour
  that "messages shorter than the length floor are exempt".
  A folded length of exactly ``min_length`` is **not**
  exempt, because "shorter than" is strict; the floor is the
  first length at which the counter applies.
* :func:`validate_dupe_exempt` — return a structured
  :class:`DupeExemptResult` that bundles the verdict with
  the comparison form, the folded length, and the threshold
  the caller supplied. The result is the same shape every
  other validator in this toolkit returns: a frozen dataclass
  with a ``valid`` flag, a typed payload, and a static
  ``reason`` that never echoes the input value.
* :data:`DUPE_EXEMPT_VERSION` — the contract version of the
  exemption API. Bumped whenever the public behaviour
  changes in a way callers can observe (different length
  rule, different comparison form, different error surface).

Security model
--------------

* Pure function over its inputs. No I/O of any kind, no
  subprocess, no network, no signing, no posting, no
  consultation of any server-side cache or ``/config``
  endpoint. The caller supplies the ``min_length`` floor;
  the module does not read it from anywhere.
* The function does not inspect, evaluate, decode, follow,
  or otherwise act on the input beyond delegating to
  :func:`dupe_form` for the canonical fold.
* :class:`DupeExemptError` carries a static message that
  never echoes the input value, because the input is
  untrusted data and the validator must not amplify it
  onto any channel.
* Idempotence in the verdict: ``dupe_exempt(text, n)``
  depends only on the documented fold and the supplied
  floor; it is deterministic, allocation-light, and
  re-entrant safe.
* The module does not enforce the documented window
  (``dupe_filter_seconds``) or the copy threshold
  (``dupe_max_copies``). It answers a single, narrow
  question — *would this text be exempt from the length
  floor on a server whose ``dupe_min_length`` is the
  supplied value?* — and exposes a stable verdict plus
  enough context to log or reason about the result.

Why a separate module
---------------------

``technocore_dupe_form`` covers the canonical fold;
``technocore_verify`` covers the cryptographic lane;
``technocore_nonce`` covers the strictly-increasing nonce
lane; ``technocore_sweep`` covers the single-line
character-substitution lane; ``technocore_sig_shape``
covers the surface form of the signature string. None of
those modules bundles the *policy* of when the fold is
exempt from the server's 5-copy counter, because the
exemption depends on a per-server configuration value the
caller owns. This module gives bridges, relays, log
replayers, and conformance harnesses a single, testable
reference for that policy.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from src.technocore_dupe_form import dupe_form


#: Integer version of the dupe-exempt contract. Bumped
#: whenever the public behaviour of :func:`dupe_exempt` or
#: :func:`validate_dupe_exempt` changes in a way that
#: callers can observe (different length rule, different
#: comparison form, different error types, different
#: exempt/inclusive boundary). The value is informational;
#: callers should pin against the test suite, not this
#: integer.
DUPE_EXEMPT_VERSION: int = 1


class DupeExemptError(ValueError):
    """Raised when :func:`validate_dupe_exempt` rejects a candidate.

    The error carries a static message; it never echoes the
    offending value, because the input is untrusted data and
    the validator must not amplify it onto any channel.
    """


@dataclass(frozen=True)
class DupeExemptResult:
    """Outcome of :func:`validate_dupe_exempt`.

    Attributes:
        valid: True only when ``text`` is a Python ``str`` and
            ``min_length`` is a non-negative integer. A ``True``
            verdict means the inputs were accepted and the
            exemption policy was applied; it does **not** mean
            the text is exempt — see :attr:`exempt` for that.
        exempt: True when the folded length of ``text`` is
            strictly less than ``min_length``. A length equal
            to the floor is **not** exempt, because the
            documented rule is "shorter than the length
            floor". ``None`` when ``valid`` is False.
        folded: The canonical duplicate-filter form of
            ``text`` (the same value :func:`dupe_form`
            returns). ``None`` when ``valid`` is False.
        folded_length: The length, in Unicode codepoints, of
            ``folded``. Equal to ``len(folded)`` when
            ``valid`` is True. ``None`` when ``valid`` is
            False.
        min_length: The length-floor threshold the caller
            supplied. Echoed back so a caller that lost
            track of its own configuration can log it. This
            is **not** the input text; it is a non-negative
            integer. ``None`` when ``valid`` is False.
        reason: Short human-readable explanation when
            ``valid`` is False. ``None`` when ``valid`` is
            True.
    """

    valid: bool
    exempt: Optional[bool]
    folded: Optional[str]
    folded_length: Optional[int]
    min_length: Optional[int]
    reason: Optional[str]


def dupe_exempt(text: str, min_length: int) -> bool:
    """Return ``True`` if ``text`` is exempt from the dupe-filter floor.

    A text is exempt when its canonical duplicate-filter form
    (:func:`dupe_form`) has length strictly less than
    ``min_length``. A folded length of exactly ``min_length``
    is **not** exempt, because the documented rule is
    "messages shorter than the length floor are exempt".

    The floor is a per-server configuration value
    (``dupe_min_length`` on ``/config``); the caller owns
    it. This function does not read it from anywhere.

    Args:
        text: A Python ``str``. Treated as untrusted data;
            the function does not echo it on any channel.
        min_length: Non-negative integer. The length floor
            below which the server's 5-copy counter does
            not apply. ``0`` disables the floor (every
            message is exempt, including the empty string).

    Returns:
        True when the folded length of ``text`` is strictly
        less than ``min_length``; False otherwise.

    Raises:
        TypeError: if ``text`` is not a ``str``.
        TypeError: if ``min_length`` is not an ``int`` (or
            is a ``bool``, which is a subclass of ``int``
            but is not a legal length here).
        ValueError: if ``min_length`` is negative.
    """
    if not isinstance(text, str):
        raise TypeError("text must be a str")
    if isinstance(min_length, bool) or not isinstance(min_length, int):
        raise TypeError("min_length must be a non-negative int")
    if min_length < 0:
        raise ValueError("min_length must be non-negative")
    return len(dupe_form(text)) < min_length


def validate_dupe_exempt(text: object, min_length: object) -> DupeExemptResult:
    """Return a structured verdict for the dupe-filter exemption policy.

    Args:
        text: Any value. Treated as untrusted data.
        min_length: Any value. Treated as a length floor; the
            caller is expected to supply a non-negative
            integer.

    Returns:
        :class:`DupeExemptResult` with ``valid`` set only
        when ``text`` is a ``str`` and ``min_length`` is a
        non-negative integer. On success, ``exempt``,
        ``folded``, ``folded_length``, and ``min_length``
        are populated. The result never echoes ``text``;
        ``min_length`` is echoed back only because it is a
        non-negative integer the caller supplied.
    """
    if not isinstance(text, str):
        return DupeExemptResult(False, None, None, None, None, "text must be a string")
    if isinstance(min_length, bool) or not isinstance(min_length, int):
        return DupeExemptResult(False, None, None, None, None, "min_length must be a non-negative int")
    if min_length < 0:
        return DupeExemptResult(False, None, None, None, None, "min_length must be non-negative")
    folded = dupe_form(text)
    folded_length = len(folded)
    return DupeExemptResult(
        valid=True,
        exempt=(folded_length < min_length),
        folded=folded,
        folded_length=folded_length,
        min_length=min_length,
        reason=None,
    )


__all__ = [
    "DUPE_EXEMPT_VERSION",
    "DupeExemptError",
    "DupeExemptResult",
    "dupe_exempt",
    "validate_dupe_exempt",
]
