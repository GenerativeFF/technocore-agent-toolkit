"""Reference implementation of the Technocore dupe-filter decision.

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

The toolkit already exposes three pure-function companions:

* :mod:`technocore_dupe_form` — the canonical fold (NFKC +
  casefold + whitespace fold) used as the comparison key;
* :mod:`technocore_dupe_exempt` — whether the folded length
  falls strictly below the caller-supplied ``min_length``
  floor (the per-server ``dupe_min_length`` value);
* :mod:`technocore_dupe_window` — whether the caller's view of
  the recent copy history would refuse the text under the
  window policy.

Every integrator that wants to predict the 5-copy counter
from outside the server ends up writing the same three-step
glue:

    if float(window_seconds) == 0:
        # filter disabled -> the text lands.
        land = True
    elif dupe_exempt(text, min_length):
        # length-floor exemption -> the text lands.
        land = True
    else:
        # window policy -> the text lands when the count of
        # recent copies inside the window is below max_copies.
        land = not dupe_window_check(
            text, history,
            window_seconds=window_seconds,
            max_copies=max_copies,
            min_length=min_length,
            now=now,
        )

This module centralises that three-step glue as a single,
testable, side-effect-free function so the comparison form,
the length-floor exemption, and the window policy live in
exactly one place per integrator. The module is a thin
*orchestrator* over the three legs; it adds no behaviour,
no new fold, no new wire format, and no new state.

What this module does
---------------------

* :func:`dupe_decision` — return ``True`` when the supplied
  text would **land** under the documented three-step policy,
  ``False`` when the text would be refused. The function
  applies the three legs in the documented order
  (disabled-filter short-circuit, length-floor exemption,
  window counter), matches the manual chain every integrator
  would otherwise write, and exposes the same verdict the
  other validators in this toolkit expose.
* :func:`validate_dupe_decision` — return a structured
  :class:`DupeDecisionResult` that bundles the verdict with
  every input the caller needs to log or reason about the
  result: ``would_land``, ``refused``, ``filter_active``,
  ``folded``, ``folded_length``, ``exempt``,
  ``copies_in_window``, ``max_copies``, ``min_length``, and
  ``window_seconds``. The result is the same shape every
  other validator in this toolkit returns: a frozen dataclass
  with a ``valid`` flag, a typed payload, and a static
  ``reason`` that never echoes the input value.
* :data:`DUPE_DECISION_VERSION` — the contract version of the
  decision API. Bumped whenever the public behaviour of
  :func:`dupe_decision` or :func:`validate_dupe_decision`
  changes in a way callers can observe (different ordering of
  legs, different exempt boundary, different error surface).
* :data:`DUPE_DECISION_WINDOW_VERSION` — alias of the window
  companion's version constant, exposed so callers that pin
  against the decision API can detect any silent drift in the
  underlying window companion.

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
  :func:`dupe_form`, :func:`dupe_exempt`, and
  :func:`dupe_window_check` for the documented fold,
  exemption policy, and window policy. Each delegation is a
  well-known pure function; the orchestrator only sequences
  them.
* :class:`DupeDecisionError` and the structured
  :class:`DupeDecisionResult` both carry static messages
  that never echo the input value, because the input is
  untrusted data and the validator must not amplify it onto
  any channel.
* Idempotence in the verdict: ``dupe_decision(text, h, ...)``
  depends only on the documented fold, the supplied
  configuration, and the supplied history; it is
  deterministic, allocation-light, and re-entrant safe.
* The module does not change any existing leg. It is a thin
  orchestrator over :func:`dupe_form`, :func:`dupe_exempt`,
  and :func:`dupe_window_check`, and any change to a leg is
  reflected automatically by the orchestrator's parity tests.

Why a separate module
--------------------

``technocore_dupe_form`` covers the canonical fold;
``technocore_dupe_exempt`` covers the length-floor exemption
policy; ``technocore_dupe_window`` covers the window-based
counter; ``technocore_verify`` covers the cryptographic
lane; ``technocore_nonce`` covers the strictly-increasing
nonce lane; ``technocore_sweep`` covers the single-line
character-substitution lane; ``technocore_sig_shape`` covers
the surface form of the signature string. None of those
modules bundles the *three-step policy* the spec asks the
sender to apply, because the policy combines a per-server
configuration value (``dupe_filter_seconds``), a per-server
configuration value (``dupe_max_copies``), a per-server
configuration value (``dupe_min_length``), and a per-server
log of recent copies (which the caller does not own).

This module gives bridges, relays, log replayers, and
conformance harnesses a single, testable reference for the
three-step policy. Callers that previously wrote the chain
inline now call :func:`dupe_decision`; callers that want a
structured verdict (for logging, retry logic, or dashboards)
call :func:`validate_dupe_decision`.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Sequence, Tuple, Union

from src.technocore_dupe_exempt import dupe_exempt
from src.technocore_dupe_form import dupe_form
from src.technocore_dupe_window import (
    DUPE_WINDOW_VERSION,
    dupe_window_check,
    validate_dupe_window,
)


#: Integer version of the dupe-decision contract. Bumped
#: whenever the public behaviour of :func:`dupe_decision` or
#: :func:`validate_dupe_decision` changes in a way that
#: callers can observe (different ordering of legs,
#: different exempt boundary, different error surface).
#: The value is informational; callers should pin against
#: the test suite, not this integer.
DUPE_DECISION_VERSION: int = 1


#: Alias of the window companion's version constant. Exposed
#: so callers that pin against the decision API can detect
#: any silent drift in the underlying window companion.
#: The two constants are pinned to be equal by the test suite.
DUPE_DECISION_WINDOW_VERSION: int = DUPE_WINDOW_VERSION


#: A history entry is a ``(text, timestamp)`` pair where
#: ``text`` is the canonical duplicate-filter form (as
#: produced by :func:`dupe_form`) and ``timestamp`` is a
#: Unix-seconds number (``int`` or ``float``). This is the
#: same shape the window companion expects.
DupeDecisionHistoryEntry = Tuple[str, Union[int, float]]


class DupeDecisionError(ValueError):
    """Raised when :func:`dupe_decision` rejects a candidate.

    The error carries a static message; it never echoes the
    offending value, because the input is untrusted data and
    the orchestrator must not amplify it onto any channel.
    """


@dataclass(frozen=True)
class DupeDecisionResult:
    """Outcome of :func:`validate_dupe_decision`.

    Attributes:
        valid: True only when every input is well-typed and
            ``window_seconds`` / ``max_copies`` /
            ``min_length`` are non-negative; ``now`` is a
            number or ``None``; and every history entry is a
            2-element sequence of ``(str, number)``. A
            ``True`` verdict means the inputs were accepted
            and the three-step policy was applied; it does
            **not** mean the text lands — see
            :attr:`would_land` for that.
        would_land: True when the text would land under the
            documented policy (filter disabled, length-floor
            exempt, or window counter below threshold).
            ``None`` when ``valid`` is False. The inverse of
            :attr:`refused` for valid results.
        refused: True when the text would be refused by the
            window-based counter: the filter is active, the
            text is not exempt from the length floor, and the
            count of matching copies inside the window is at
            least ``max_copies``. ``None`` when ``valid`` is
            False.
        filter_active: True when ``window_seconds`` is not
            zero (i.e., the server's window-based counter is
            enabled). ``None`` when ``valid`` is False.
        folded: The canonical duplicate-filter form of
            ``text`` (the same value :func:`dupe_form`
            returns). ``None`` when ``valid`` is False.
        folded_length: The length, in Unicode codepoints, of
            ``folded``. Equal to ``len(folded)`` when
            ``valid`` is True. ``None`` when ``valid`` is
            False.
        exempt: True when :func:`dupe_exempt` reports the
            text as exempt from the length floor. ``None``
            when ``valid`` is False. A length-equal-to-floor
            text is **not** exempt (``dupe_exempt`` is
            strict).
        copies_in_window: The number of history entries
            whose folded form equals ``folded`` and whose
            timestamp falls strictly inside the window
            (``now - ts < window_seconds``). When the filter
            is disabled or the text is exempt, this is 0.
            ``None`` when ``valid`` is False.
        min_length: The length-floor threshold the caller
            supplied. Echoed back so a caller that lost track
            of its own configuration can log it. This is
            **not** the input text; it is a non-negative
            integer. ``None`` when ``valid`` is False.
        max_copies: The copy-count threshold the caller
            supplied. Echoed back because it is a
            non-negative integer the caller supplied.
            ``None`` when ``valid`` is False.
        window_seconds: The window length the caller
            supplied, in seconds. Echoed back as a
            ``float`` (``0`` disables the filter).
            ``None`` when ``valid`` is False.
        reason: Short human-readable explanation when
            ``valid`` is False. Static and parameter-free;
            never echoes ``text``, ``history``, or any
            caller-supplied value. ``None`` when ``valid``
            is True.
        dupe_decision_version: The contract version of the
            decision API (echoes :data:`DUPE_DECISION_VERSION`).
        dupe_window_version: The window companion's contract
            version (echoes :data:`DUPE_DECISION_WINDOW_VERSION`).
    """

    valid: bool
    would_land: Optional[bool]
    refused: Optional[bool]
    filter_active: Optional[bool]
    folded: Optional[str]
    folded_length: Optional[int]
    exempt: Optional[bool]
    copies_in_window: Optional[int]
    min_length: Optional[int]
    max_copies: Optional[int]
    window_seconds: Optional[float]
    reason: Optional[str]
    dupe_decision_version: int
    dupe_window_version: int


def _validate(
    text: object,
    history: object,
    window_seconds: object,
    max_copies: object,
    min_length: object,
    now: object,
) -> Optional[str]:
    """Return a static reason when any argument is invalid, else ``None``.

    Single source of truth for the argument-validation
    surface of the decision orchestrator. Reason strings are
    parameter-free; they never echo the offending value.
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
    for idx, entry in enumerate(history):
        if not isinstance(entry, (list, tuple)) or len(entry) != 2:
            return f"history[{idx}] must be a 2-element sequence"
        entry_text, entry_ts = entry
        if not isinstance(entry_text, str):
            return f"history[{idx}][0] must be a string"
        if isinstance(entry_ts, bool) or not isinstance(entry_ts, (int, float)):
            return f"history[{idx}][1] must be a number"
    if now is not None:
        if isinstance(now, bool) or not isinstance(now, (int, float)):
            return "now must be a number or None"
    return None


def _raise_from_reason(reason: str) -> NoReturn:  # type: ignore[name-defined]
    """Map a static validation reason to the matching Python ``Exception``.

    The mapping mirrors the window companion's classification:
    type errors (wrong container, wrong scalar type, wrong
    entry shape) raise ``TypeError``; range errors (negative
    numbers) raise ``ValueError``. Reasons never carry the
    offending value, so callers cannot accidentally amplify
    untrusted input through the exception message.
    """
    # Local import keeps the orchestration surface tight.
    from typing import NoReturn  # noqa: F401  pylint: disable=import-outside-toplevel,reimported

    if reason == "text must be a string":
        raise TypeError("text must be a str")
    if reason == "history must be a sequence of (folded_text, timestamp) pairs":
        raise TypeError(reason)
    if reason in (
        "window_seconds must be a non-negative number",
        "max_copies must be a non-negative int",
        "min_length must be a non-negative int",
        "now must be a number or None",
    ):
        raise TypeError(reason)
    if reason.startswith("history[") and (
        "must be a 2-element sequence" in reason
        or "must be a string" in reason
        or "must be a number" in reason
    ):
        raise TypeError(reason)
    raise ValueError(reason)


def dupe_decision(
    text: str,
    history: Sequence[DupeDecisionHistoryEntry],
    *,
    window_seconds: Union[int, float],
    max_copies: int,
    min_length: int = 0,
    now: Optional[Union[int, float]] = None,
) -> bool:
    """Return ``True`` if ``text`` would land under the three-step policy.

    The orchestrator applies the three documented legs in
    order:

    1. **Disabled-filter short-circuit.** When
       ``window_seconds`` is zero, the filter is disabled and
       the text lands — regardless of the history, the copy
       threshold, or the length floor. This matches the
       documented "0 on the window disables the filter"
       rule.
    2. **Length-floor exemption.** When :func:`dupe_exempt`
       reports the folded length of ``text`` is strictly
       less than ``min_length``, the text lands — regardless
       of the history or the copy threshold. A folded length
       exactly equal to ``min_length`` is **not** exempt, per
       the documented "shorter than the length floor"
       language.
    3. **Window counter.** Otherwise, the text lands when
       :func:`dupe_window_check` reports the history does
       not refuse it; the orchestrator returns the negation
       of the window verdict.

    Args:
        text: A Python ``str``. Treated as untrusted data;
            the function does not echo it on any channel.
        history: A sequence of ``(folded_text, timestamp)``
            pairs representing the caller's view of the
            recent copies on the server. ``folded_text``
            is the canonical duplicate-filter form (as
            produced by :func:`dupe_form`); ``timestamp``
            is a Unix-seconds number (``int`` or ``float``).
            The caller owns this view; a stale view yields a
            stale prediction.
        window_seconds: Non-negative number. The window
            length in seconds. ``0`` disables the filter
            (every text lands). The caller owns this value;
            this function does not read it from any server.
        max_copies: Non-negative integer. The copy-count
            threshold: the first ``max_copies`` copies of a
            folded form inside the window land, and the
            ``(max_copies + 1)``-th is refused. ``0`` means
            "no copies allowed", which refuses every
            non-exempt text (including the first copy).
        min_length: Non-negative integer. The length floor
            below which the text is exempt. ``0`` disables
            the floor (no exemption).
        now: Optional reference time for the window check.
            When ``None``, the window companion uses the
            latest timestamp in ``history`` (or ``0.0`` if
            the history is empty). When supplied, the value
            is passed through to the window companion
            unchanged.

    Returns:
        ``True`` when the text would land under the
        three-step policy; ``False`` when it would be
        refused.

    Raises:
        TypeError: if any argument has the wrong Python type.
        ValueError: if any numeric argument is negative.
    """
    reason = _validate(text, history, window_seconds, max_copies, min_length, now)
    if reason is not None:
        _raise_from_reason(reason)
    # The validator has narrowed the types; re-bind for the
    # type checker.
    history_typed: Sequence[DupeDecisionHistoryEntry] = history  # type: ignore[assignment]
    window_seconds_f = float(window_seconds)
    max_copies_i = int(max_copies)
    min_length_i = int(min_length)

    # Leg 1: disabled-filter short-circuit.
    if window_seconds_f == 0:
        return True
    # Leg 2: length-floor exemption.
    if dupe_exempt(text, min_length_i):
        return True
    # Leg 3: window counter.
    return not dupe_window_check(
        text,
        history_typed,
        window_seconds=window_seconds_f,
        max_copies=max_copies_i,
        min_length=min_length_i,
        now=now,
    )


def validate_dupe_decision(
    text: object,
    history: object,
    *,
    window_seconds: object,
    max_copies: object,
    min_length: object = 0,
    now: object = None,
) -> DupeDecisionResult:
    """Return a structured verdict for the three-step policy.

    Args:
        text: Any value. Treated as untrusted data.
        history: Any value. Treated as a history sequence;
            the caller is expected to supply a list or tuple
            of 2-element sequences of ``(str, number)``.
        window_seconds: Any value. Treated as a window length;
            the caller is expected to supply a non-negative
            number.
        max_copies: Any value. Treated as a copy-count
            threshold; the caller is expected to supply a
            non-negative integer.
        min_length: Any value. Treated as a length floor; the
            caller is expected to supply a non-negative
            integer.
        now: Any value. Treated as a reference time; the
            caller is expected to supply a number or
            ``None``.

    Returns:
        :class:`DupeDecisionResult` with ``valid`` set only
        when every argument has the documented type. On
        success, ``would_land``, ``refused``, ``filter_active``,
        ``folded``, ``folded_length``, ``exempt``,
        ``copies_in_window``, ``max_copies``, ``min_length``,
        and ``window_seconds`` are populated. The result
        never echoes ``text``; ``folded`` is the *transformed*
        output, not the input. ``window_seconds``,
        ``max_copies``, and ``min_length`` are echoed back
        only because they are caller-supplied configuration
        values.
    """
    reason = _validate(text, history, window_seconds, max_copies, min_length, now)
    if reason is not None:
        return DupeDecisionResult(
            valid=False,
            would_land=None,
            refused=None,
            filter_active=None,
            folded=None,
            folded_length=None,
            exempt=None,
            copies_in_window=None,
            min_length=None,
            max_copies=None,
            window_seconds=None,
            reason=reason,
            dupe_decision_version=DUPE_DECISION_VERSION,
            dupe_window_version=DUPE_DECISION_WINDOW_VERSION,
        )
    text_n: str = text  # type: ignore[assignment]
    history_n: Sequence[DupeDecisionHistoryEntry] = history  # type: ignore[assignment]
    window_seconds_n: Union[int, float] = window_seconds  # type: ignore[assignment]
    max_copies_n: int = max_copies  # type: ignore[assignment]
    min_length_n: int = min_length  # type: ignore[assignment]
    now_n: Optional[Union[int, float]] = now  # type: ignore[assignment]

    folded = dupe_form(text_n)
    folded_length = len(folded)
    filter_active = float(window_seconds_n) != 0
    exempt = dupe_exempt(text_n, int(min_length_n))

    # Leg 1: disabled-filter short-circuit.
    if not filter_active:
        return DupeDecisionResult(
            valid=True,
            would_land=True,
            refused=False,
            filter_active=False,
            folded=folded,
            folded_length=folded_length,
            exempt=exempt,
            copies_in_window=0,
            min_length=int(min_length_n),
            max_copies=int(max_copies_n),
            window_seconds=float(window_seconds_n),
            reason=None,
            dupe_decision_version=DUPE_DECISION_VERSION,
            dupe_window_version=DUPE_DECISION_WINDOW_VERSION,
        )
    # Leg 2: length-floor exemption. The folded length
    # is computed once so the result can be inspected by
    # callers without re-folding.
    if exempt:
        return DupeDecisionResult(
            valid=True,
            would_land=True,
            refused=False,
            filter_active=True,
            folded=folded,
            folded_length=folded_length,
            exempt=True,
            copies_in_window=0,
            min_length=int(min_length_n),
            max_copies=int(max_copies_n),
            window_seconds=float(window_seconds_n),
            reason=None,
            dupe_decision_version=DUPE_DECISION_VERSION,
            dupe_window_version=DUPE_DECISION_WINDOW_VERSION,
        )
    # Leg 3: window counter. Delegate the count and the
    # verdict to the window companion so the parity is
    # exact.
    window = validate_dupe_window(
        text_n,
        history_n,
        window_seconds=window_seconds_n,
        max_copies=max_copies_n,
        min_length=min_length_n,
        now=now_n,
    )
    refused = bool(window.refused)
    return DupeDecisionResult(
        valid=True,
        would_land=not refused,
        refused=refused,
        filter_active=True,
        folded=folded,
        folded_length=folded_length,
        exempt=False,
        copies_in_window=window.copies_in_window,
        min_length=int(min_length_n),
        max_copies=int(max_copies_n),
        window_seconds=float(window_seconds_n),
        reason=None,
        dupe_decision_version=DUPE_DECISION_VERSION,
        dupe_window_version=DUPE_DECISION_WINDOW_VERSION,
    )


__all__ = [
    "DUPE_DECISION_VERSION",
    "DUPE_DECISION_WINDOW_VERSION",
    "DupeDecisionHistoryEntry",
    "DupeDecisionError",
    "DupeDecisionResult",
    "dupe_decision",
    "validate_dupe_decision",
]
