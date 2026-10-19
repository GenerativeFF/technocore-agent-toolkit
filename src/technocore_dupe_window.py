"""Reference implementation of the Technocore dupe-filter window check.

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
casefold + whitespace fold) and :mod:`technocore_dupe_exempt`
exposes the *length-floor exemption policy*. Neither module
answers the third question the spec asks the sender to
answer: *would this text be refused by the server's
window-based counter right now?* That question requires
knowing the recent history of copies, which is server-side
state the caller does not own.

This module gives bridges, relays, log replayers, and
conformance harnesses a single, testable, side-effect-free
function that takes the caller's view of the recent history
and returns the same verdict the server would return. The
function is a *prediction*, not a server query: the caller
supplies the history because the server is the source of
truth, and a stale history yields a stale prediction.

What this module does
---------------------

* :func:`dupe_window_check` — return ``True`` when a text
  would be refused by the server's window-based counter,
  given a caller-supplied history of recent copies. The
  function folds the text with :func:`dupe_form`, counts the
  history entries whose folded form equals the folded text
  and whose timestamp falls inside the window, and compares
  the count against the caller-supplied ``max_copies``
  threshold. Texts exempt from the length floor (per
  :func:`dupe_exempt`) are never refused. A
  ``window_seconds`` of 0 disables the filter, matching the
  documented "0 on the window disables the filter" rule.
* :func:`validate_dupe_window` — return a structured
  :class:`DupeWindowResult` that bundles the verdict with
  the folded form, the observed copy count inside the
  window, the supplied threshold, the supplied window, and
  the reason on failure. The result is the same shape every
  other validator in this toolkit returns: a frozen
  dataclass with a ``valid`` flag, a typed payload, and a
  static ``reason`` that never echoes the input value.
* :data:`DUPE_WINDOW_VERSION` — the contract version of the
  window-check API. Bumped whenever the public behaviour
  changes in a way callers can observe (different counting
  rule, different exempt boundary, different error surface).

Security model
--------------

* Pure function over its inputs. No I/O of any kind, no
  subprocess, no network, no signing, no posting, no
  consultation of any server-side cache or ``/config``
  endpoint. The caller supplies the window, the copy
  threshold, the length floor, and the history; the module
  does not read any of them from anywhere.
* The function does not inspect, evaluate, decode, follow,
  or otherwise act on the input beyond delegating to
  :func:`dupe_form` and :func:`dupe_exempt` for the
  documented fold and exemption policy.
* :class:`DupeWindowError` carries a static message that
  never echoes the input value, because the input is
  untrusted data and the validator must not amplify it onto
  any channel.
* The structured result never echoes the input ``text`` on
  any channel; ``folded`` is the *transformed* output, not
  the input. ``window_seconds``, ``max_copies``, and
  ``min_length`` are echoed back only because they are
  caller-supplied configuration values.
* Idempotence in the verdict: ``dupe_window_check(text, h, ...)``
  depends only on the documented fold, the supplied
  history, and the supplied configuration; it is
  deterministic, allocation-light, and re-entrant safe.
* The module does not enforce the documented window
  (``dupe_filter_seconds``) or the copy threshold
  (``dupe_max_copies``) by itself; it answers a single,
  narrow question — *would this text be refused by a server
  whose ``dupe_filter_seconds``, ``dupe_max_copies``, and
  ``dupe_min_length`` are the supplied values, given the
  supplied history?* — and exposes a stable verdict plus
  enough context to log or reason about the result.

Why a separate module
---------------------

``technocore_dupe_form`` covers the canonical fold;
``technocore_dupe_exempt`` covers the length-floor
exemption; ``technocore_verify`` covers the cryptographic
lane; ``technocore_nonce`` covers the strictly-increasing
nonce lane; ``technocore_sweep`` covers the single-line
character-substitution lane; ``technocore_sig_shape``
covers the surface form of the signature string. None of
those modules bundles the *window* part of the duplicate
filter, because the window requires the caller to know
the recent history of copies on the server. This module
gives bridges, relays, log replayers, and conformance
harnesses a single, testable reference for the window
check.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional, Sequence, Tuple, Union

from src.technocore_dupe_exempt import dupe_exempt
from src.technocore_dupe_form import dupe_form


#: Integer version of the dupe-window contract. Bumped
#: whenever the public behaviour of :func:`dupe_window_check`
#: or :func:`validate_dupe_window` changes in a way that
#: callers can observe (different counting rule, different
#: exempt boundary, different error types, different default
#: for the ``now`` argument). The value is informational;
#: callers should pin against the test suite, not this
#: integer.
DUPE_WINDOW_VERSION: int = 1


#: A history entry is a ``(folded_text, timestamp)`` pair
#: where ``folded_text`` is the canonical duplicate-filter
#: form (as produced by :func:`dupe_form`) and ``timestamp``
#: is a Unix-seconds number (``int`` or ``float``).
DupeWindowEntry = Tuple[str, Union[int, float]]


class DupeWindowError(ValueError):
    """Raised when :func:`validate_dupe_window` rejects a candidate.

    The error carries a static message; it never echoes the
    offending value, because the input is untrusted data and
    the validator must not amplify it onto any channel.
    """


@dataclass(frozen=True)
class DupeWindowResult:
    """Outcome of :func:`validate_dupe_window`.

    Attributes:
        valid: True only when ``text`` is a Python ``str`` and
            every configuration argument is a legal value. A
            ``True`` verdict means the inputs were accepted and
            the window policy was applied; it does **not** mean
            the text is refused — see :attr:`refused` for that.
        refused: True when the text would be refused by the
            server's window-based counter (i.e., the number of
            matching copies inside the window is greater than or
            equal to ``max_copies``, and the text is not exempt
            from the length floor, and the filter is not
            disabled). False when the text would land. ``None``
            when ``valid`` is False.
        folded: The canonical duplicate-filter form of
            ``text`` (the same value :func:`dupe_form` returns).
            ``None`` when ``valid`` is False.
        copies_in_window: The number of history entries whose
            folded form equals ``folded`` and whose timestamp
            falls strictly inside the window (i.e.,
            ``now - ts < window_seconds``). ``None`` when
            ``valid`` is False.
        max_copies: The copy-count threshold the caller
            supplied. Echoed back so a caller that lost track
            of its own configuration can log it. This is
            **not** the input text; it is a non-negative
            integer. ``None`` when ``valid`` is False.
        window_seconds: The window length the caller supplied,
            in seconds. ``0`` disables the filter. ``None``
            when ``valid`` is False.
        reason: Short human-readable explanation when
            ``valid`` is False. ``None`` when ``valid`` is
            True.
    """

    valid: bool
    refused: Optional[bool]
    folded: Optional[str]
    copies_in_window: Optional[int]
    max_copies: Optional[int]
    window_seconds: Optional[Union[int, float]]
    reason: Optional[str]


def _validate_config(
    text: object,
    history: object,
    window_seconds: object,
    max_copies: object,
    min_length: object,
) -> Optional[str]:
    """Return a static reason string when the config is invalid, else ``None``.

    This helper is the single source of truth for the
    argument-validation surface of the window check. It never
    echoes the input value; reasons are static, parameter-free
    strings.
    """
    if not isinstance(text, str):
        return "text must be a string"
    if not isinstance(history, (list, tuple)):
        return "history must be a sequence of (folded_text, timestamp) pairs"
    if isinstance(window_seconds, bool) or not isinstance(window_seconds, (int, float)):
        return "window_seconds must be a non-negative number"
    if window_seconds < 0:
        return "window_seconds must be non-negative"
    if isinstance(max_copies, bool) or not isinstance(max_copies, int):
        return "max_copies must be a non-negative int"
    if max_copies < 0:
        return "max_copies must be non-negative"
    if isinstance(min_length, bool) or not isinstance(min_length, int):
        return "min_length must be a non-negative int"
    if min_length < 0:
        return "min_length must be non-negative"
    # Validate every history entry. Each entry must be a
    # 2-element sequence whose first element is a str and
    # whose second element is a number. The validator does
    # not echo the entry value.
    for idx, entry in enumerate(history):
        if not isinstance(entry, (list, tuple)) or len(entry) != 2:
            return f"history[{idx}] must be a 2-element sequence"
        entry_text, entry_ts = entry
        if not isinstance(entry_text, str):
            return f"history[{idx}][0] must be a string"
        if isinstance(entry_ts, bool) or not isinstance(entry_ts, (int, float)):
            return f"history[{idx}][1] must be a number"
    return None


def dupe_window_check(
    text: str,
    history: Sequence[DupeWindowEntry],
    *,
    window_seconds: Union[int, float],
    max_copies: int,
    min_length: int = 0,
    now: Optional[Union[int, float]] = None,
) -> bool:
    """Return ``True`` if ``text`` would be refused by the dupe-filter window.

    A text is refused when:

    1. The filter is not disabled (``window_seconds`` is not 0).
    2. The text is not exempt from the length floor (per
       :func:`dupe_exempt` with the supplied ``min_length``).
    3. The number of history entries whose folded form equals
       the folded form of ``text`` and whose timestamp falls
       strictly inside the window is greater than or equal to
       ``max_copies``.

    The window is a half-open interval ``(now - window_seconds, now]``:
    a copy at timestamp ``ts`` is inside the window when
    ``now - ts < window_seconds``. A copy exactly at the
    boundary (``now - ts == window_seconds``) is **not** inside
    the window, matching the "inside the window" language of
    the spec.

    The ``now`` argument is the reference time used to
    evaluate the window. When omitted, the function uses the
    latest timestamp in ``history``; when ``history`` is
    empty, the function returns ``False`` (no copies to
    count, so the text is never refused).

    Args:
        text: A Python ``str``. Treated as untrusted data;
            the function does not echo it on any channel.
        history: A sequence of ``(folded_text, timestamp)``
            pairs representing the caller's view of the recent
            copies on the server. ``folded_text`` is the
            canonical duplicate-filter form (as produced by
            :func:`dupe_form`); ``timestamp`` is a Unix-seconds
            number (``int`` or ``float``). The caller owns
            this view; a stale view yields a stale prediction.
        window_seconds: Non-negative number. The window
            length in seconds. ``0`` disables the filter
            (no text is ever refused). This matches the
            documented "0 on the window disables the filter"
            rule.
        max_copies: Non-negative integer. The copy-count
            threshold: the first ``max_copies`` copies of a
            folded form inside the window land, and the
            ``(max_copies + 1)``-th is refused. A value of
            ``0`` means "no copies allowed", which refuses
            every non-exempt text (including the first copy).
        min_length: Non-negative integer. The length floor
            below which the text is exempt from the counter.
            ``0`` disables the floor (no exemption). The
            caller owns this value; this function does not
            read it from any server.
        now: Optional reference time for the window check.
            When ``None``, the function uses the latest
            timestamp in ``history`` (or returns ``False``
            when ``history`` is empty).

    Returns:
        ``True`` when the text would be refused by the
        server's window-based counter; ``False`` when it
        would land.

    Raises:
        TypeError: if any argument has the wrong Python type.
        ValueError: if any numeric argument is negative.
    """
    reason = _validate_config(text, history, window_seconds, max_copies, min_length)
    if reason is not None:
        # The validator returns static, parameter-free reason
        # strings; the input is never echoed. Map the
        # ``text must be a string`` reason to a TypeError
        # because the Python API raises TypeError on a bad
        # ``text`` type (mirroring :func:`dupe_form` and
        # :func:`dupe_exempt`).
        if reason == "text must be a string":
            raise TypeError("text must be a str")
        # History shape errors are TypeError because the
        # caller passed the wrong container type.
        if reason == "history must be a sequence of (folded_text, timestamp) pairs":
            raise TypeError("history must be a sequence of (folded_text, timestamp) pairs")
        # window_seconds / max_copies / min_length type
        # errors are TypeError because the caller passed the
        # wrong scalar type.
        if reason in (
            "window_seconds must be a non-negative number",
            "max_copies must be a non-negative int",
            "min_length must be a non-negative int",
        ):
            raise TypeError(reason)
        # History entry shape errors are TypeError because
        # the caller passed a malformed entry.
        if reason.startswith("history[") and (
            "must be a 2-element sequence" in reason
            or "must be a string" in reason
            or "must be a number" in reason
        ):
            raise TypeError(reason)
        # Remaining reasons are range errors (negative
        # numbers), which are ValueError.
        raise ValueError(reason)
    # At this point, ``history`` is a list or tuple (per
    # _validate_config) and every entry is a 2-element
    # sequence of (str, number). The type checker is
    # unable to narrow the element types through the
    # _validate_config helper, so we re-bind the local
    # names to the narrowed types for the rest of the
    # function.
    history_typed: Sequence[DupeWindowEntry] = history  # type: ignore[assignment]
    window_seconds_f = float(window_seconds)
    max_copies_i = int(max_copies)
    min_length_i = int(min_length)

    # window_seconds=0 disables the filter: no text is ever
    # refused, regardless of the length floor or the copy
    # count. This matches the documented "0 on the window
    # disables the filter" rule.
    if window_seconds_f == 0:
        return False

    # Exempt texts (folded length strictly less than the
    # length floor) are never refused. The fold and the
    # exemption check are pure functions; this branch is a
    # short-circuit, not a semantic change.
    if dupe_exempt(text, min_length_i):
        return False

    folded = dupe_form(text)

    # Resolve the reference time. When ``now`` is supplied,
    # use it directly (and validate that it is a number —
    # _validate_config already did that for the keyword
    # argument, but the caller may have passed ``now`` as a
    # positional or keyword with a bad type that bypassed the
    # helper). When ``now`` is ``None`` and ``history`` is
    # non-empty, use the latest timestamp. When both are
    # absent, return False (no copies to count).
    if now is not None:
        if isinstance(now, bool) or not isinstance(now, (int, float)):
            raise TypeError("now must be a number or None")
        now_f = float(now)
    elif history_typed:
        now_f = float(max(ts for _, ts in history_typed))
    else:
        # No history and no reference time: the count of
        # copies inside the window is 0, so the window
        # check reduces to ``0 >= max_copies``. This means
        # a non-exempt text with ``max_copies == 0`` is
        # refused (the "no copies allowed" interpretation),
        # and a non-exempt text with ``max_copies > 0`` is
        # not refused (the "first copy lands" behaviour).
        now_f = 0.0

    # Count history entries whose folded form equals
    # ``folded`` and whose timestamp falls strictly inside
    # the window (``now - ts < window_seconds``). A copy
    # exactly at the boundary is NOT inside the window.
    count = 0
    for entry_text, entry_ts in history_typed:
        if entry_text == folded and (now_f - float(entry_ts)) < window_seconds_f:
            count += 1

    # The first ``max_copies`` copies land; the
    # ``(max_copies + 1)``-th is refused. So the text is
    # refused when the count of prior copies inside the
    # window is already ``max_copies`` or more.
    return count >= max_copies_i


def validate_dupe_window(
    text: object,
    history: object,
    *,
    window_seconds: object,
    max_copies: object,
    min_length: object = 0,
    now: object = None,
) -> DupeWindowResult:
    """Return a structured verdict for the dupe-filter window policy.

    Args:
        text: Any value. Treated as untrusted data.
        history: Any value. Treated as a history sequence;
            the caller is expected to supply a list or tuple
            of 2-element sequences of ``(str, number)``.
        window_seconds: Any value. Treated as a window
            length; the caller is expected to supply a
            non-negative number.
        max_copies: Any value. Treated as a copy-count
            threshold; the caller is expected to supply a
            non-negative integer.
        min_length: Any value. Treated as a length floor;
            the caller is expected to supply a non-negative
            integer.
        now: Any value. Treated as a reference time; the
            caller is expected to supply a number or
            ``None``.

    Returns:
        :class:`DupeWindowResult` with ``valid`` set only
        when every argument has the documented type. On
        success, ``refused``, ``folded``,
        ``copies_in_window``, ``max_copies``, and
        ``window_seconds`` are populated. The result never
        echoes ``text``; ``folded`` is the *transformed*
        output, not the input. ``window_seconds``,
        ``max_copies``, and ``min_length`` are echoed back
        only because they are caller-supplied configuration
        values.
    """
    reason = _validate_config(text, history, window_seconds, max_copies, min_length)
    if reason is not None:
        return DupeWindowResult(
            valid=False,
            refused=None,
            folded=None,
            copies_in_window=None,
            max_copies=None,
            window_seconds=None,
            reason=reason,
        )
    # Validate ``now`` here (the Python API validates it
    # inside the function body, but the validator path
    # returns a structured result instead of raising).
    if now is not None:
        if isinstance(now, bool) or not isinstance(now, (int, float)):
            return DupeWindowResult(
                valid=False,
                refused=None,
                folded=None,
                copies_in_window=None,
                max_copies=None,
                window_seconds=None,
                reason="now must be a number or None",
            )
    # Narrow the types for the rest of the function. The
    # validator has confirmed every argument; the type
    # checker cannot infer the narrowing through the helper.
    text_n: str = text  # type: ignore[assignment]
    history_n: Sequence[DupeWindowEntry] = history  # type: ignore[assignment]
    window_seconds_n: Union[int, float] = window_seconds  # type: ignore[assignment]
    max_copies_n: int = max_copies  # type: ignore[assignment]
    min_length_n: int = min_length  # type: ignore[assignment]
    now_n: Optional[Union[int, float]] = now  # type: ignore[assignment]

    # window_seconds=0 disables the filter.
    if float(window_seconds_n) == 0:
        return DupeWindowResult(
            valid=True,
            refused=False,
            folded=dupe_form(text_n),
            copies_in_window=0,
            max_copies=int(max_copies_n),
            window_seconds=float(window_seconds_n),
            reason=None,
        )

    # Exempt texts are never refused.
    if dupe_exempt(text_n, int(min_length_n)):
        return DupeWindowResult(
            valid=True,
            refused=False,
            folded=dupe_form(text_n),
            copies_in_window=0,
            max_copies=int(max_copies_n),
            window_seconds=float(window_seconds_n),
            reason=None,
        )

    folded = dupe_form(text_n)

    # Resolve the reference time.
    if now_n is not None:
        now_f = float(now_n)
    elif history_n:
        now_f = float(max(ts for _, ts in history_n))
    else:
        # No history and no reference time: the count of
        # copies inside the window is 0, so the window
        # check reduces to ``0 >= max_copies``. This means
        # a non-exempt text with ``max_copies == 0`` is
        # refused (the "no copies allowed" interpretation),
        # and a non-exempt text with ``max_copies > 0`` is
        # not refused (the "first copy lands" behaviour).
        now_f = 0.0

    window_seconds_f = float(window_seconds_n)
    count = 0
    for entry_text, entry_ts in history_n:
        if entry_text == folded and (now_f - float(entry_ts)) < window_seconds_f:
            count += 1

    refused = count >= int(max_copies_n)
    return DupeWindowResult(
        valid=True,
        refused=refused,
        folded=folded,
        copies_in_window=count,
        max_copies=int(max_copies_n),
        window_seconds=window_seconds_f,
        reason=None,
    )


__all__ = [
    "DUPE_WINDOW_VERSION",
    "DupeWindowEntry",
    "DupeWindowError",
    "DupeWindowResult",
    "dupe_window_check",
    "validate_dupe_window",
]
