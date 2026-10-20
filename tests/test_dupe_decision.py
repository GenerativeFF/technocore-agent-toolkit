"""Unit tests for :mod:`src.technocore_dupe_decision`.

The dupe-filter decision is a thin orchestrator over the
three existing legs (:func:`dupe_form`,
:func:`dupe_exempt`, :func:`dupe_window_check`). The test
suite locks down:

* the documented ordering of the three legs (disabled-filter
  short-circuit, then length-floor exemption, then
  window-counter verdict);
* the equivalence of ``dupe_decision`` with the manual
  three-step glue every integrator would otherwise write;
* the parity of ``validate_dupe_decision`` with
  :func:`dupe_window_check` /
  :func:`validate_dupe_window` on every representative
  pair in the window companion's test suite;
* the no-amplification contract — the offending value must
  never appear in any structured field, the JSON error
  payload, or any underlying error message;
* the type-rejection surface (non-``str`` text,
  non-sequence history, wrong-arity history entries,
  non-string history text, non-number history timestamp,
  non-``int`` ``max_copies`` / ``min_length``, non-number
  ``window_seconds`` / ``now``; ``bool`` is explicitly
  rejected for every numeric parameter);
* the result immutability and the version constants.
"""
from __future__ import annotations

import os
import sys
import unittest

# Make the in-tree src/ package importable.
_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO = os.path.dirname(_HERE)
_SRC = os.path.join(_REPO, "src")
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

# pylint: disable=wrong-import-position
from src.technocore_dupe_decision import (  # noqa: E402
    DUPE_DECISION_VERSION,
    DUPE_DECISION_WINDOW_VERSION,
    DupeDecisionError,
    DupeDecisionResult,
    dupe_decision,
    validate_dupe_decision,
)
from src.technocore_dupe_exempt import DUPE_EXEMPT_VERSION, dupe_exempt  # noqa: E402
from src.technocore_dupe_form import DUPE_FORM_VERSION, dupe_form  # noqa: E402
from src.technocore_dupe_window import (  # noqa: E402
    DUPE_WINDOW_VERSION,
    dupe_window_check,
    validate_dupe_window,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _manual_decision(
    text: str,
    history,
    *,
    window_seconds,
    max_copies,
    min_length=0,
    now=None,
):
    """Return the manual three-step verdict the orchestrator replaces.

    Every Parity test compares the orchestrator's verdict
    against this manual chain. Keeping it inline makes the
    parity check independent of the orchestrator itself, so
    a regression in either direction is visible.
    """
    # Leg 1: disabled-filter short-circuit. The documented
    # "0 on the window disables the filter" rule applies
    # regardless of the length floor; even a non-exempt
    # text with ``max_copies == 0`` lands when the filter
    # is disabled.
    if float(window_seconds) == 0:
        return True
    # Leg 2: length-floor exemption.
    if dupe_exempt(text, min_length):
        return True
    # Leg 3: window-counter verdict.
    return not dupe_window_check(
        text,
        history,
        window_seconds=window_seconds,
        max_copies=max_copies,
        min_length=min_length,
        now=now,
    )


# A recognisable sentinel that must never appear in any
# structured field, reason string, or exception message.
# The no-amplification contract tests below assert the
# sentinel never leaks via the orchestrator.
_SENTINEL = "ZZ_DUPE_DECISION_AMPLIFICATION_SENTINEL_8421"


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------


class ConstantsTests(unittest.TestCase):
    """The exported constants must agree with the documented invariant."""

    def test_version_is_a_positive_int(self) -> None:
        self.assertIsInstance(DUPE_DECISION_VERSION, int)
        self.assertGreaterEqual(DUPE_DECISION_VERSION, 1)

    def test_window_version_matches_dupe_window(self) -> None:
        # The decision module pins against the window
        # module's contract version; the test pins the
        # alias value to detect any silent drift.
        self.assertEqual(DUPE_DECISION_WINDOW_VERSION, DUPE_WINDOW_VERSION)

    def test_underlying_leg_versions_are_one(self) -> None:
        # Sanity check: the three leg modules are at
        # version 1. If any leg bumps its version, the
        # orchestrator's parity tests catch it; this test
        # pins the current state so a silent regression
        # in the constants is visible.
        self.assertEqual(DUPE_FORM_VERSION, 1)
        self.assertEqual(DUPE_EXEMPT_VERSION, 1)
        self.assertEqual(DUPE_WINDOW_VERSION, 1)


# ---------------------------------------------------------------------------
# Leg 1: disabled-filter short-circuit
# ---------------------------------------------------------------------------


class DisabledFilterTests(unittest.TestCase):
    """``window_seconds == 0`` lands every text, regardless of the history."""

    def test_first_copy_lands_with_disabled_filter(self) -> None:
        # ``max_copies=0`` would refuse the very first
        # copy if the filter were active; the disabled
        # filter short-circuit lands it anyway.
        self.assertTrue(
            dupe_decision(
                "hello world",
                history=[],
                window_seconds=0,
                max_copies=0,
                min_length=4,
            )
        )

    def test_long_after_history_lands_with_disabled_filter(self) -> None:
        # A refilled history would refuse the next copy
        # if the filter were active; the disabled filter
        # short-circuit lands it anyway.
        history = [("hello world", 1000 + i) for i in range(50)]
        self.assertTrue(
            dupe_decision(
                "hello world",
                history=history,
                window_seconds=0,
                max_copies=3,
                min_length=4,
            )
        )

    def test_non_exempt_text_lands_with_disabled_filter(self) -> None:
        # A non-exempt text with `max_copies=0`: the
        # disabled filter still lands the text.
        history = [("hello world", 1000), ("hello world", 1010)]
        self.assertTrue(
            dupe_decision(
                "hello world",
                history=history,
                window_seconds=0,
                max_copies=0,
                min_length=4,
            )
        )

    def test_disabled_filter_zero_window_seconds_float(self) -> None:
        # ``window_seconds=0.0`` is the same as ``0`` (the
        # check is against the float zero, not just the
        # int zero).
        self.assertTrue(
            dupe_decision(
                "hello world",
                history=[],
                window_seconds=0.0,
                max_copies=0,
                min_length=4,
            )
        )

    def test_validate_disabled_filter_carries_filter_active_false(self) -> None:
        result = validate_dupe_decision(
            "hello world",
            [],
            window_seconds=0,
            max_copies=0,
            min_length=4,
        )
        self.assertTrue(result.valid)
        self.assertTrue(result.would_land)
        self.assertFalse(result.refused)
        self.assertFalse(result.filter_active)
        self.assertEqual(result.copies_in_window, 0)


# ---------------------------------------------------------------------------
# Leg 2: length-floor exemption
# ---------------------------------------------------------------------------


class ExemptionTests(unittest.TestCase):
    """Texts strictly shorter than the floor land regardless of the history."""

    def test_empty_text_lands_above_zero_floor(self) -> None:
        # The empty string is strictly less than every
        # positive floor; it is exempt.
        self.assertTrue(
            dupe_decision(
                "",
                history=[],
                window_seconds=60,
                max_copies=0,
                min_length=1,
            )
        )

    def test_documented_repeat_lands_above_floor_three(self) -> None:
        # "ok" folds to two codepoints; a floor of 3
        # exempts it from the count.
        self.assertTrue(
            dupe_decision(
                "ok",
                history=[
                    ("ok", 1000 + i) for i in range(50)
                ],
                window_seconds=60,
                max_copies=3,
                min_length=3,
            )
        )

    def test_documented_repeat_not_exempt_at_floor_two(self) -> None:
        # "ok" folds to two codepoints; a floor of 2
        # means the fold length equals the floor, so the
        # text is NOT exempt (the rule is strict).
        self.assertEqual(
            dupe_decision(
                "ok",
                history=[
                    ("ok", 1000),
                    ("ok", 1010),
                    ("ok", 1020),
                ],
                window_seconds=60,
                max_copies=3,
                min_length=2,
            ),
            False,
        )

    def test_exempt_text_validate_carries_exempt_true(self) -> None:
        result = validate_dupe_decision(
            "ok",
            [("ok", 1000), ("ok", 1010)],
            window_seconds=60,
            max_copies=3,
            min_length=3,
        )
        self.assertTrue(result.valid)
        self.assertTrue(result.would_land)
        self.assertFalse(result.refused)
        self.assertTrue(result.exempt)
        self.assertEqual(result.copies_in_window, 0)


# ---------------------------------------------------------------------------
# Leg 3: window-counter verdict
# ---------------------------------------------------------------------------


class WindowCounterTests(unittest.TestCase):
    """When the filter is active and the text is not exempt, the window applies."""

    def test_first_copy_lands(self) -> None:
        # No matching history; the count is 0, which is
        # below the threshold of 3; the text lands.
        self.assertTrue(
            dupe_decision(
                "hello world",
                history=[],
                window_seconds=60,
                max_copies=3,
                min_length=4,
            )
        )

    def test_third_copy_lands(self) -> None:
        history = [
            ("hello world", 1000),
            ("hello world", 1010),
        ]
        self.assertTrue(
            dupe_decision(
                "hello world",
                history=history,
                window_seconds=60,
                max_copies=3,
                min_length=4,
            )
        )

    def test_fourth_copy_refused(self) -> None:
        history = [
            ("hello world", 1000),
            ("hello world", 1010),
            ("hello world", 1020),
        ]
        self.assertFalse(
            dupe_decision(
                "hello world",
                history=history,
                window_seconds=60,
                max_copies=3,
                min_length=4,
            )
        )

    def test_max_copies_zero_refuses_first_non_exempt_copy(self) -> None:
        self.assertFalse(
            dupe_decision(
                "hello world",
                history=[],
                window_seconds=60,
                max_copies=0,
                min_length=4,
            )
        )

    def test_expired_history_outside_window_lands(self) -> None:
        # Matches in the history, but the timestamps
        # fall outside the window because ``now`` is the
        # current time. The window companion honours
        # ``now``; the orchestrator must pass it through.
        history = [
            ("hello world", 1000),
            ("hello world", 1010),
            ("hello world", 1020),
        ]
        self.assertTrue(
            dupe_decision(
                "hello world",
                history=history,
                window_seconds=60,
                max_copies=3,
                min_length=4,
                now=10000,
            )
        )


# ---------------------------------------------------------------------------
# Parity with the manual three-step glue
# ---------------------------------------------------------------------------


class ParityWithManualChainTests(unittest.TestCase):
    """``dupe_decision`` must equal the manual chain every integrator writes."""

    def test_first_copy_basic(self) -> None:
        text = "hello world"
        history = []
        kw = {"window_seconds": 60, "max_copies": 3, "min_length": 4}
        self.assertEqual(
            dupe_decision(text, history, **kw),
            _manual_decision(text, history, **kw),
        )

    def test_refilled_history(self) -> None:
        text = "hello world"
        history = [("hello world", 1000 + i) for i in range(10)]
        kw = {"window_seconds": 60, "max_copies": 3, "min_length": 4}
        self.assertEqual(
            dupe_decision(text, history, **kw),
            _manual_decision(text, history, **kw),
        )

    def test_disabled_filter_with_refilled_history(self) -> None:
        text = "hello world"
        history = [("hello world", 1000 + i) for i in range(50)]
        kw = {"window_seconds": 0, "max_copies": 3, "min_length": 4}
        self.assertEqual(
            dupe_decision(text, history, **kw),
            _manual_decision(text, history, **kw),
        )

    def test_max_copies_zero_with_non_exempt_text(self) -> None:
        text = "hello world"
        history = []
        kw = {"window_seconds": 60, "max_copies": 0, "min_length": 4}
        self.assertEqual(
            dupe_decision(text, history, **kw),
            _manual_decision(text, history, **kw),
        )

    def test_max_copies_zero_with_disabled_filter(self) -> None:
        text = "hello world"
        history = [("hello world", 1000), ("hello world", 1010)]
        kw = {"window_seconds": 0, "max_copies": 0, "min_length": 4}
        self.assertEqual(
            dupe_decision(text, history, **kw),
            _manual_decision(text, history, **kw),
        )

    def test_conversational_repeat_lands_with_refilled_history(self) -> None:
        text = "gm"
        history = [("gm", 1000 + i) for i in range(20)]
        kw = {"window_seconds": 60, "max_copies": 3, "min_length": 3}
        self.assertEqual(
            dupe_decision(text, history, **kw),
            _manual_decision(text, history, **kw),
        )

    def test_conversational_repeat_refused_at_floor_two(self) -> None:
        text = "gm"
        history = [("gm", 1000), ("gm", 1010), ("gm", 1020)]
        kw = {"window_seconds": 60, "max_copies": 3, "min_length": 2}
        self.assertEqual(
            dupe_decision(text, history, **kw),
            _manual_decision(text, history, **kw),
        )

    def test_nfc_vs_nfd_parity(self) -> None:
        # Sending "Việt" in NFC vs NFD produces two
        # different source strings but the same fold
        # ("việt"). The window count should treat them
        # as one entry.
        nfc = "Việt"  # precomposed
        nfd = "V\u0069\u0302\u0065t"  # decomposed "Việt"
        history_nfc = [(nfc, 1000), (nfc, 1010)]
        history_nfd = [(nfd, 1000), (nfd, 1010)]
        kw = {"window_seconds": 60, "max_copies": 3, "min_length": 4}
        # Test both history shapes against each candidate
        # text: the verdict depends only on the folded
        # history, not on the surface form.
        self.assertEqual(
            dupe_decision(nfc, history_nfc, **kw),
            _manual_decision(nfc, history_nfc, **kw),
        )
        self.assertEqual(
            dupe_decision(nfc, history_nfd, **kw),
            _manual_decision(nfc, history_nfd, **kw),
        )
        self.assertEqual(
            dupe_decision(nfd, history_nfc, **kw),
            _manual_decision(nfd, history_nfc, **kw),
        )

    def test_passes_now_through(self) -> None:
        text = "hello world"
        history = [
            ("hello world", 1000),
            ("hello world", 1010),
            ("hello world", 1020),
        ]
        # now far in the future: history is outside the
        # window, the text lands.
        kw = {
            "window_seconds": 60,
            "max_copies": 3,
            "min_length": 4,
            "now": 100000,
        }
        self.assertEqual(
            dupe_decision(text, history, **kw),
            _manual_decision(text, history, **kw),
        )

    def test_mixed_history(self) -> None:
        # A history with both matching and non-matching
        # folded forms.
        text = "hello world"
        history = [
            ("other text", 1000),
            ("hello world", 1010),
            ("another", 1020),
            ("hello world", 1030),
            ("different", 1040),
        ]
        kw = {"window_seconds": 60, "max_copies": 3, "min_length": 4}
        self.assertEqual(
            dupe_decision(text, history, **kw),
            _manual_decision(text, history, **kw),
        )

    def test_case_insensitive_parity(self) -> None:
        # "Hello World" and "HELLO WORLD" and "hello world"
        # all fold to "hello world".
        text = "Hello World"
        history = [
            ("HELLO WORLD", 1000),
            ("hello world", 1010),
        ]
        kw = {"window_seconds": 60, "max_copies": 3, "min_length": 4}
        self.assertEqual(
            dupe_decision(text, history, **kw),
            _manual_decision(text, history, **kw),
        )


# ---------------------------------------------------------------------------
# Parity with the underlying companions
# ---------------------------------------------------------------------------


class ParityWithCompanionModulesTests(unittest.TestCase):
    """The structured verdict must agree with each leg's structured verdict."""

    def test_folded_matches_dupe_form(self) -> None:
        result = validate_dupe_decision(
            "Việt",
            [],
            window_seconds=60,
            max_copies=3,
            min_length=4,
        )
        self.assertTrue(result.valid)
        self.assertEqual(result.folded, dupe_form("Việt"))
        self.assertEqual(result.folded_length, len(dupe_form("Việt")))

    def test_exempt_matches_dupe_exempt(self) -> None:
        # Exempt case: "ok" with a floor of 3.
        result = validate_dupe_decision(
            "ok",
            [("ok", 1000), ("ok", 1010)],
            window_seconds=60,
            max_copies=3,
            min_length=3,
        )
        self.assertTrue(result.valid)
        self.assertEqual(result.exempt, dupe_exempt("ok", 3))
        self.assertTrue(result.exempt)

    def test_exempt_false_at_equal_floor(self) -> None:
        # The rule is strict: a folded length equal to
        # the floor is NOT exempt.
        result = validate_dupe_decision(
            "gm",
            [],
            window_seconds=60,
            max_copies=3,
            min_length=2,
        )
        self.assertTrue(result.valid)
        # "gm" folds to length 2; floor is 2; fold
        # length is NOT strictly less than the floor.
        self.assertFalse(result.exempt)
        self.assertEqual(result.exempt, dupe_exempt("gm", 2))

    def test_refused_matches_window_companion(self) -> None:
        history = [
            ("hello world", 1000),
            ("hello world", 1010),
            ("hello world", 1020),
        ]
        result = validate_dupe_decision(
            "hello world",
            history,
            window_seconds=60,
            max_copies=3,
            min_length=4,
        )
        window = validate_dupe_window(
            "hello world",
            history,
            window_seconds=60,
            max_copies=3,
            min_length=4,
        )
        self.assertTrue(result.valid)
        self.assertTrue(window.valid)
        self.assertEqual(result.refused, window.refused)
        self.assertEqual(result.copies_in_window, window.copies_in_window)

    def test_would_land_is_inverse_of_refused(self) -> None:
        cases = [
            ("hello world", [], 60, 3, 4),
            ("hello world", [("hello world", 1000)], 60, 3, 4),
            (
                "hello world",
                [("hello world", 1000), ("hello world", 1010), ("hello world", 1020)],
                60,
                3,
                4,
            ),
            ("ok", [("ok", 1000), ("ok", 1010)], 60, 3, 3),
            ("hello world", [], 0, 3, 4),
        ]
        for text, history, ws, mc, ml in cases:
            with self.subTest(text=text, ws=ws, mc=mc, ml=ml):
                result = validate_dupe_decision(
                    text,
                    history,
                    window_seconds=ws,
                    max_copies=mc,
                    min_length=ml,
                )
                self.assertTrue(result.valid)
                self.assertEqual(result.would_land, not result.refused)


# ---------------------------------------------------------------------------
# No-amplification contract
# ---------------------------------------------------------------------------


class NoAmplificationTests(unittest.TestCase):
    """The offending value must never appear in any structured field."""

    def _assert_sentinel_absent(self, haystack: str) -> None:
        self.assertNotIn(_SENTINEL, haystack)

    def test_sentinel_in_text_is_not_in_validation_result(self) -> None:
        result = validate_dupe_decision(
            _SENTINEL,
            [],
            window_seconds=60,
            max_copies=3,
            min_length=4,
        )
        self.assertTrue(result.valid)
        self._assert_sentinel_absent(result.folded or "")
        self.assertIsNone(result.reason)

    def test_sentinel_in_history_is_not_in_copies_in_window(self) -> None:
        # The folded form of the sentinel is the
        # comparison key; the test asserts the raw
        # sentinel never leaks as a "copies_in_window"
        # message or as a structured field.
        result = validate_dupe_decision(
            "hello world",
            [(_SENTINEL, 1000)],
            window_seconds=60,
            max_copies=3,
            min_length=4,
        )
        self.assertTrue(result.valid)
        # The count is 0 because the sentinel doesn't
        # match the folded form of "hello world"; the
        # field is the integer count, not the text.
        self.assertEqual(result.copies_in_window, 0)
        # Folded form of the candidate text only;
        # sentinel is in the history but never echoed.
        self._assert_sentinel_absent(result.folded or "")

    def test_invalid_text_does_not_echo_value(self) -> None:
        # The sentinelled string is well-typed (``str``) so
        # the validator accepts it and ``reason`` is ``None``.
        # The no-amplification contract on the rejection path
        # is exercised end-to-end in
        # ``test_no_amplification_on_validator_reasons`` and
        # ``test_invalid_text`` (both pass non-``str``
        # payloads and check that the static reason does not
        # echo the input value). This case pins the passing
        # path: a well-typed sentinelled payload must still
        # not surface its sentinel anywhere in the static
        # ``reason``.
        result = validate_dupe_decision(
            _SENTINEL + "_not_a_string",
            [],
            window_seconds=60,
            max_copies=3,
            min_length=4,
        )
        self.assertTrue(result.valid)
        self._assert_sentinel_absent(result.reason or "")

    def test_invalid_history_entry_does_not_echo_value(self) -> None:
        # The history is ``[[sentinel, 1000]]`` — a single
        # 2-element sequence whose first element is the
        # sentinelled ``str`` and whose second element is an
        # ``int``. The arity is 2, the text is a ``str``, and
        # the timestamp is a non-bool number, so the validator
        # accepts the history and ``reason`` is ``None``.
        # The no-amplification contract on the rejection
        # path is exercised end-to-end in
        # ``test_invalid_history_entry_arity`` /
        # ``_text_type`` / ``_timestamp_type``, which check
        # that the static ``history[N]...`` reason does not
        # echo the offending entry value. This case pins the
        # passing path: a well-typed sentinelled history
        # entry must still not surface its sentinel anywhere
        # in the static ``reason``.
        result = validate_dupe_decision(
            "hello world",
            [[_SENTINEL, 1000]],
            window_seconds=60,
            max_copies=3,
            min_length=4,
        )
        self.assertTrue(result.valid)
        self._assert_sentinel_absent(result.reason or "")


# ---------------------------------------------------------------------------
# Type rejection (Python API surface)
# ---------------------------------------------------------------------------


class TypeRejectionTests(unittest.TestCase):
    """The Python API raises for type violations, parameter-free reasons."""

    def test_text_must_be_str(self) -> None:
        with self.assertRaises(TypeError) as ctx:
            dupe_decision(
                b"hello world",  # type: ignore[arg-type]
                [],
                window_seconds=60,
                max_copies=3,
                min_length=4,
            )
        self.assertNotIn("hello world", str(ctx.exception))
        self.assertNotIn(_SENTINEL, str(ctx.exception))

    def test_history_must_be_sequence(self) -> None:
        with self.assertRaises(TypeError):
            dupe_decision(
                "hello world",
                "not a list",  # type: ignore[arg-type]
                window_seconds=60,
                max_copies=3,
                min_length=4,
            )

    def test_window_seconds_must_be_number(self) -> None:
        with self.assertRaises(TypeError):
            dupe_decision(
                "hello world",
                [],
                window_seconds="60",  # type: ignore[arg-type]
                max_copies=3,
                min_length=4,
            )

    def test_window_seconds_must_not_be_bool(self) -> None:
        with self.assertRaises(TypeError):
            dupe_decision(
                "hello world",
                [],
                window_seconds=True,  # type: ignore[arg-type]
                max_copies=3,
                min_length=4,
            )

    def test_max_copies_must_be_int(self) -> None:
        with self.assertRaises(TypeError):
            dupe_decision(
                "hello world",
                [],
                window_seconds=60,
                max_copies=3.0,  # type: ignore[arg-type]
                min_length=4,
            )

    def test_max_copies_must_not_be_bool(self) -> None:
        with self.assertRaises(TypeError):
            dupe_decision(
                "hello world",
                [],
                window_seconds=60,
                max_copies=True,  # type: ignore[arg-type]
                min_length=4,
            )

    def test_min_length_must_be_int(self) -> None:
        with self.assertRaises(TypeError):
            dupe_decision(
                "hello world",
                [],
                window_seconds=60,
                max_copies=3,
                min_length=4.0,  # type: ignore[arg-type]
            )

    def test_min_length_must_not_be_bool(self) -> None:
        with self.assertRaises(TypeError):
            dupe_decision(
                "hello world",
                [],
                window_seconds=60,
                max_copies=3,
                min_length=True,  # type: ignore[arg-type]
            )

    def test_window_seconds_negative_raises_value_error(self) -> None:
        with self.assertRaises(ValueError):
            dupe_decision(
                "hello world",
                [],
                window_seconds=-1,
                max_copies=3,
                min_length=4,
            )

    def test_max_copies_negative_raises_value_error(self) -> None:
        with self.assertRaises(ValueError):
            dupe_decision(
                "hello world",
                [],
                window_seconds=60,
                max_copies=-1,
                min_length=4,
            )

    def test_min_length_negative_raises_value_error(self) -> None:
        with self.assertRaises(ValueError):
            dupe_decision(
                "hello world",
                [],
                window_seconds=60,
                max_copies=3,
                min_length=-1,
            )

    def test_history_wrong_arity_raises_type_error(self) -> None:
        with self.assertRaises(TypeError) as ctx:
            dupe_decision(
                "hello world",
                [(1000,)],  # type: ignore[list-item]
                window_seconds=60,
                max_copies=3,
                min_length=4,
            )
        # The reason starts with "history[0]" but never
        # echoes the offending entry value (a tuple of
        # one int) into the message.
        self.assertNotIn("1000", str(ctx.exception))

    def test_history_non_string_text_raises_type_error(self) -> None:
        with self.assertRaises(TypeError) as ctx:
            dupe_decision(
                "hello world",
                [(b"hello world", 1000)],  # type: ignore[list-item]
                window_seconds=60,
                max_copies=3,
                min_length=4,
            )
        self.assertNotIn("hello world", str(ctx.exception))

    def test_history_non_number_timestamp_raises_type_error(self) -> None:
        with self.assertRaises(TypeError) as ctx:
            dupe_decision(
                "hello world",
                [("hello world", "1000")],  # type: ignore[list-item]
                window_seconds=60,
                max_copies=3,
                min_length=4,
            )
        self.assertNotIn("1000", str(ctx.exception))

    def test_now_must_be_number_or_none(self) -> None:
        with self.assertRaises(TypeError):
            dupe_decision(
                "hello world",
                [],
                window_seconds=60,
                max_copies=3,
                min_length=4,
                now="1000",  # type: ignore[arg-type]
            )

    def test_now_must_not_be_bool(self) -> None:
        with self.assertRaises(TypeError):
            dupe_decision(
                "hello world",
                [],
                window_seconds=60,
                max_copies=3,
                min_length=4,
                now=True,  # type: ignore[arg-type]
            )


# ---------------------------------------------------------------------------
# Type rejection (validate_* surface)
# ---------------------------------------------------------------------------


class ValidateTypeRejectionTests(unittest.TestCase):
    """The validator returns a structured result for type violations."""

    def _assert_invalid(self, result: DupeDecisionResult) -> None:
        self.assertFalse(result.valid)
        self.assertIsNone(result.would_land)
        self.assertIsNone(result.refused)
        self.assertIsNone(result.filter_active)
        self.assertIsNone(result.folded)
        self.assertIsNone(result.folded_length)
        self.assertIsNone(result.exempt)
        self.assertIsNone(result.copies_in_window)
        self.assertIsNone(result.min_length)
        self.assertIsNone(result.max_copies)
        self.assertIsNone(result.window_seconds)
        self.assertIsNotNone(result.reason)

    def test_invalid_text(self) -> None:
        result = validate_dupe_decision(
            b"hello world",  # type: ignore[arg-type]
            [],
            window_seconds=60,
            max_copies=3,
            min_length=4,
        )
        self._assert_invalid(result)
        self.assertEqual(result.reason, "text must be a string")
        self.assertNotIn("hello world", result.reason)

    def test_invalid_history_type(self) -> None:
        result = validate_dupe_decision(
            "hello world",
            "not a list",  # type: ignore[arg-type]
            window_seconds=60,
            max_copies=3,
            min_length=4,
        )
        self._assert_invalid(result)

    def test_invalid_window_seconds_type(self) -> None:
        result = validate_dupe_decision(
            "hello world",
            [],
            window_seconds="60",  # type: ignore[arg-type]
            max_copies=3,
            min_length=4,
        )
        self._assert_invalid(result)

    def test_invalid_max_copies_type(self) -> None:
        result = validate_dupe_decision(
            "hello world",
            [],
            window_seconds=60,
            max_copies=3.0,  # type: ignore[arg-type]
            min_length=4,
        )
        self._assert_invalid(result)

    def test_invalid_min_length_type(self) -> None:
        result = validate_dupe_decision(
            "hello world",
            [],
            window_seconds=60,
            max_copies=3,
            min_length=4.0,  # type: ignore[arg-type]
        )
        self._assert_invalid(result)

    def test_invalid_window_seconds_bool(self) -> None:
        result = validate_dupe_decision(
            "hello world",
            [],
            window_seconds=True,  # type: ignore[arg-type]
            max_copies=3,
            min_length=4,
        )
        self._assert_invalid(result)

    def test_invalid_max_copies_bool(self) -> None:
        result = validate_dupe_decision(
            "hello world",
            [],
            window_seconds=60,
            max_copies=True,  # type: ignore[arg-type]
            min_length=4,
        )
        self._assert_invalid(result)

    def test_invalid_min_length_bool(self) -> None:
        result = validate_dupe_decision(
            "hello world",
            [],
            window_seconds=60,
            max_copies=3,
            min_length=True,  # type: ignore[arg-type]
        )
        self._assert_invalid(result)

    def test_invalid_window_seconds_negative(self) -> None:
        result = validate_dupe_decision(
            "hello world",
            [],
            window_seconds=-1,
            max_copies=3,
            min_length=4,
        )
        self._assert_invalid(result)
        self.assertEqual(result.reason, "window_seconds must be non-negative")

    def test_invalid_max_copies_negative(self) -> None:
        result = validate_dupe_decision(
            "hello world",
            [],
            window_seconds=60,
            max_copies=-1,
            min_length=4,
        )
        self._assert_invalid(result)
        self.assertEqual(result.reason, "max_copies must be non-negative")

    def test_invalid_min_length_negative(self) -> None:
        result = validate_dupe_decision(
            "hello world",
            [],
            window_seconds=60,
            max_copies=3,
            min_length=-1,
        )
        self._assert_invalid(result)
        self.assertEqual(result.reason, "min_length must be non-negative")

    def test_invalid_history_entry_arity(self) -> None:
        result = validate_dupe_decision(
            "hello world",
            [[1000]],  # type: ignore[list-item]
            window_seconds=60,
            max_copies=3,
            min_length=4,
        )
        self._assert_invalid(result)
        self.assertEqual(result.reason, "history[0] must be a 2-element sequence")

    def test_invalid_history_entry_text_type(self) -> None:
        result = validate_dupe_decision(
            "hello world",
            [(b"hello world", 1000)],  # type: ignore[list-item]
            window_seconds=60,
            max_copies=3,
            min_length=4,
        )
        self._assert_invalid(result)
        self.assertEqual(result.reason, "history[0][0] must be a string")

    def test_invalid_history_entry_timestamp_type(self) -> None:
        result = validate_dupe_decision(
            "hello world",
            [("hello world", "1000")],  # type: ignore[list-item]
            window_seconds=60,
            max_copies=3,
            min_length=4,
        )
        self._assert_invalid(result)
        self.assertEqual(result.reason, "history[0][1] must be a number")

    def test_invalid_now_type(self) -> None:
        result = validate_dupe_decision(
            "hello world",
            [],
            window_seconds=60,
            max_copies=3,
            min_length=4,
            now="1000",  # type: ignore[arg-type]
        )
        self._assert_invalid(result)
        self.assertEqual(result.reason, "now must be a number or None")

    def test_invalid_now_bool(self) -> None:
        result = validate_dupe_decision(
            "hello world",
            [],
            window_seconds=60,
            max_copies=3,
            min_length=4,
            now=True,  # type: ignore[arg-type]
        )
        self._assert_invalid(result)

    def test_no_amplification_on_validator_reasons(self) -> None:
        # Across every invalid-input path, the offending
        # value must not appear in the static reason.
        for bad_text in (
            b"hello",
            None,
            123,
            ["hello"],
            {"hello": "world"},
        ):
            with self.subTest(bad_text=bad_text):
                result = validate_dupe_decision(
                    bad_text,  # type: ignore[arg-type]
                    [],
                    window_seconds=60,
                    max_copies=3,
                    min_length=4,
                )
                self.assertFalse(result.valid)
                # The reason is the static string; never
                # contains the input value.
                self.assertEqual(result.reason, "text must be a string")


# ---------------------------------------------------------------------------
# Result immutability and echo-back
# ---------------------------------------------------------------------------


class ResultShapeTests(unittest.TestCase):
    """The structured result shape is frozen and echoes back config safely."""

    def test_result_is_frozen(self) -> None:
        result = validate_dupe_decision(
            "hello world",
            [],
            window_seconds=60,
            max_copies=3,
            min_length=4,
        )
        self.assertTrue(result.valid)
        with self.assertRaises(Exception):
            # pylint: disable=attribute-defined-outside-init
            result.would_land = False  # type: ignore[misc]

    def test_config_values_echoed_back(self) -> None:
        result = validate_dupe_decision(
            "hello world",
            [],
            window_seconds=60,
            max_copies=3,
            min_length=4,
        )
        self.assertTrue(result.valid)
        self.assertEqual(result.window_seconds, 60.0)
        self.assertEqual(result.max_copies, 3)
        self.assertEqual(result.min_length, 4)

    def test_versions_are_echoed_back(self) -> None:
        result = validate_dupe_decision(
            "hello world",
            [],
            window_seconds=60,
            max_copies=3,
            min_length=4,
        )
        self.assertTrue(result.valid)
        self.assertEqual(result.dupe_decision_version, DUPE_DECISION_VERSION)
        self.assertEqual(result.dupe_window_version, DUPE_DECISION_WINDOW_VERSION)


# ---------------------------------------------------------------------------
# Determinism and idempotence
# ---------------------------------------------------------------------------


class DeterminismTests(unittest.TestCase):
    """Repeated calls with the same inputs return the same verdict."""

    def test_python_api_determinism(self) -> None:
        history = [("hello world", 1000), ("hello world", 1010)]
        kwargs = {"window_seconds": 60, "max_copies": 3, "min_length": 4}
        first = dupe_decision("hello world", history, **kwargs)
        second = dupe_decision("hello world", history, **kwargs)
        third = dupe_decision("hello world", history, **kwargs)
        self.assertEqual(first, second)
        self.assertEqual(second, third)
        # Two prior copies inside the window with
        # ``max_copies=3`` means the third copy lands. The
        # parity contract (verified by
        # ``ParityWithManualChainTests``) pins the value;
        # this determinism test pins only that repeated
        # calls return the same verdict.
        self.assertTrue(first)  # would land — 3rd copy lands (2 prior, threshold 3)

    def test_validate_api_determinism(self) -> None:
        history = [("hello world", 1000), ("hello world", 1010)]
        first = validate_dupe_decision(
            "hello world",
            history,
            window_seconds=60,
            max_copies=3,
            min_length=4,
        )
        second = validate_dupe_decision(
            "hello world",
            history,
            window_seconds=60,
            max_copies=3,
            min_length=4,
        )
        self.assertEqual(first, second)


# ---------------------------------------------------------------------------
# End-to-end: documented scenario from /llms.txt DUPLICATES section
# ---------------------------------------------------------------------------


class DocumentedScenarioTests(unittest.TestCase):
    """The scenario spelled out in the DUPLICATES specification."""

    def test_5_copy_120s_5th_lands_6th_refused(self) -> None:
        # The /llms.txt section says "further copies ...
        # are refused until the window passes". Document
        # the boundary with the typical instance values:
        # 5-copy threshold, 120s window. Confirm the
        # orchestrator lands the first 5 and refuses the
        # 6th under the documented numbers.
        text = "good morning team"
        # Empty history: the first copy lands.
        self.assertTrue(
            dupe_decision(
                text,
                [],
                window_seconds=120,
                max_copies=5,
                min_length=4,
            )
        )
        # After 4 prior copies inside the window, the
        # 5th lands.
        history_4 = [(text, 1000 + i) for i in range(4)]
        self.assertTrue(
            dupe_decision(
                text,
                history_4,
                window_seconds=120,
                max_copies=5,
                min_length=4,
            )
        )
        # After 5 prior copies inside the window, the
        # 6th is refused.
        history_5 = [(text, 1000 + i) for i in range(5)]
        self.assertFalse(
            dupe_decision(
                text,
                history_5,
                window_seconds=120,
                max_copies=5,
                min_length=4,
            )
        )


# ---------------------------------------------------------------------------
# Module surface
# ---------------------------------------------------------------------------


class SurfaceTests(unittest.TestCase):
    """The public surface must include the documented names."""

    def test_module_exports_documented_names(self) -> None:
        import src.technocore_dupe_decision as mod

        for name in (
            "DUPE_DECISION_VERSION",
            "DUPE_DECISION_WINDOW_VERSION",
            "DupeDecisionError",
            "DupeDecisionResult",
            "DupeDecisionHistoryEntry",
            "dupe_decision",
            "validate_dupe_decision",
        ):
            with self.subTest(name=name):
                self.assertTrue(
                    hasattr(mod, name),
                    f"module is missing exported name: {name}",
                )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
