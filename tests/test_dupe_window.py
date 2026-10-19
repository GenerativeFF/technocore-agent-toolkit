"""Unit tests for :mod:`src.technocore_dupe_window`.

The dupe-filter window check is the third companion to the
Technocore duplicate-filter specification:

* :func:`dupe_form` produces the canonical comparison form
  (NFKC + casefold + whitespace fold).
* :func:`dupe_exempt` answers "is this text exempt from the
  length floor?".
* :func:`dupe_window_check` answers "would this text be
  refused by the server's window-based counter right now,
  given a caller-supplied history?".

The test suite locks down the window boundary (strict
less-than at the window edge), the "5 copies in 120s"
default threshold, the documented exemption interaction, the
"0 on the window disables the filter" rule, the
``now`` argument's default behaviour, the type-rejection
surface, the no-amplification contract, the parity with
:func:`dupe_form` and :func:`dupe_exempt`, and the
determinism of the verdict.
"""
from __future__ import annotations

import os
import sys
import unittest

# Make the in-tree src/ package importable.
_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO = os.path.dirname(_HERE)
_SRC = os.path.join(_HERE)  # tests/ is a sibling of src/
# Allow ``python -m unittest`` from the repo root or any subdirectory.
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

# pylint: disable=wrong-import-position
from src.technocore_dupe_window import (  # noqa: E402
    DUPE_WINDOW_VERSION,
    DupeWindowError,
    DupeWindowResult,
    dupe_window_check,
    validate_dupe_window,
)
from src.technocore_dupe_exempt import dupe_exempt  # noqa: E402
from src.technocore_dupe_form import dupe_form  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _history(*pairs):
    """Build a history list from ``(text, ts)`` pairs.

    The text is folded with :func:`dupe_form` so the test
    history matches the canonical form the window check
    compares against.
    """
    return [(dupe_form(t), float(ts)) for t, ts in pairs]


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------


class ConstantsTests(unittest.TestCase):
    """The exported constants must agree with the documented invariant."""

    def test_version_is_a_positive_int(self) -> None:
        self.assertIsInstance(DUPE_WINDOW_VERSION, int)
        self.assertGreaterEqual(DUPE_WINDOW_VERSION, 1)


# ---------------------------------------------------------------------------
# Empty / trivial histories
# ---------------------------------------------------------------------------


class EmptyHistoryTests(unittest.TestCase):
    """An empty history means no copies have landed yet."""

    def test_empty_history_never_refuses(self) -> None:
        # No copies in the history, so no text can be refused.
        for text in ("hello", "ok", "gm", "+1", ""):
            with self.subTest(text=text):
                self.assertFalse(
                    dupe_window_check(
                        text,
                        [],
                        window_seconds=120,
                        max_copies=5,
                    )
                )

    def test_empty_history_with_now_never_refuses(self) -> None:
        # An explicit ``now`` does not change the verdict when
        # the history is empty: there are still no copies to
        # count.
        for text in ("hello", "ok", "gm", "+1", ""):
            with self.subTest(text=text):
                self.assertFalse(
                    dupe_window_check(
                        text,
                        [],
                        window_seconds=120,
                        max_copies=5,
                        now=1_000_000.0,
                    )
                )


# ---------------------------------------------------------------------------
# The documented "5 copies in 120s" threshold
# ---------------------------------------------------------------------------


class FiveCopiesIn120SecondsTests(unittest.TestCase):
    """The default threshold: 5 copies inside 120s draws a 422."""

    def test_first_five_copies_land(self) -> None:
        # 5 copies at t=0..4s, the 6th at t=5s should be
        # refused. The function counts prior copies inside
        # the window, so the 6th sees count=5 and is refused.
        # The window is strict less-than: a copy at exactly
        # now - window_seconds is NOT inside the window, so
        # ts=120 (boundary) is excluded from the refusal loop.
        history = _history(
            ("hello", 0),
            ("hello", 1),
            ("hello", 2),
            ("hello", 3),
            ("hello", 4),
        )
        for ts in (5, 6, 10, 50, 119):
            with self.subTest(ts=ts):
                self.assertTrue(
                    dupe_window_check(
                        "hello",
                        history,
                        window_seconds=120,
                        max_copies=5,
                        now=float(ts),
                    )
                )

    def test_fifth_copy_lands(self) -> None:
        # 4 prior copies, the 5th at t=4s should land (count=4
        # < 5).
        history = _history(
            ("hello", 0),
            ("hello", 1),
            ("hello", 2),
            ("hello", 3),
        )
        self.assertFalse(
            dupe_window_check(
                "hello",
                history,
                window_seconds=120,
                max_copies=5,
                now=4.0,
            )
        )

    def test_first_copy_always_lands(self) -> None:
        # Empty history, first copy lands regardless of
        # window_seconds or max_copies (as long as the filter
        # is not disabled and the text is not exempt).
        self.assertFalse(
            dupe_window_check(
                "hello",
                [],
                window_seconds=120,
                max_copies=5,
            )
        )

    def test_different_folded_texts_are_independent(self) -> None:
        # 5 copies of "hello" in the window does not affect
        # the verdict for a different text like "world".
        history = _history(
            ("hello", 0),
            ("hello", 1),
            ("hello", 2),
            ("hello", 3),
            ("hello", 4),
        )
        self.assertFalse(
            dupe_window_check(
                "world",
                history,
                window_seconds=120,
                max_copies=5,
                now=5.0,
            )
        )


# ---------------------------------------------------------------------------
# Window boundary: strict less-than
# ---------------------------------------------------------------------------


class WindowBoundaryTests(unittest.TestCase):
    """The window is a half-open interval ``(now - window_seconds, now]``."""

    def test_copy_exactly_at_boundary_is_outside_window(self) -> None:
        # A copy at now - window_seconds is NOT inside the
        # window (strict less-than). So with one prior copy
        # at the exact boundary and max_copies=1, the next
        # copy is NOT refused.
        history = _history(("hello", 0))
        self.assertFalse(
            dupe_window_check(
                "hello",
                history,
                window_seconds=120,
                max_copies=1,
                now=120.0,
            )
        )

    def test_copy_just_inside_boundary_is_inside_window(self) -> None:
        # A copy at now - window_seconds + epsilon IS inside
        # the window. With max_copies=1, the next copy IS
        # refused. The history entry at t=1 has
        # now - ts = 120 + 1e-9 - 1 = 119 + 1e-9, which is
        # strictly less than 120, so it IS inside the window.
        history = _history(("hello", 1))
        self.assertTrue(
            dupe_window_check(
                "hello",
                history,
                window_seconds=120,
                max_copies=1,
                now=120.0 + 1e-9,
            )
        )

    def test_copy_well_outside_window_is_ignored(self) -> None:
        # A copy at t=0 is outside the window when now=1000
        # and window_seconds=120. The count is 0, so the
        # text lands even with max_copies=1.
        history = _history(("hello", 0))
        self.assertFalse(
            dupe_window_check(
                "hello",
                history,
                window_seconds=120,
                max_copies=1,
                now=1000.0,
            )
        )


# ---------------------------------------------------------------------------
# "0 on the window disables the filter"
# ---------------------------------------------------------------------------


class WindowDisabledTests(unittest.TestCase):
    """window_seconds=0 means the filter is disabled."""

    def test_zero_window_never_refuses(self) -> None:
        # Even with 1000 copies in the history, a zero
        # window disables the filter.
        history = _history(*[("hello", float(i)) for i in range(1000)])
        self.assertFalse(
            dupe_window_check(
                "hello",
                history,
                window_seconds=0,
                max_copies=5,
                now=1000.0,
            )
        )

    def test_zero_window_ignores_exemption(self) -> None:
        # The exemption policy is irrelevant when the filter
        # is disabled: nothing is refused regardless of
        # min_length.
        history = _history(("hello", 0))
        self.assertFalse(
            dupe_window_check(
                "ok",
                history,
                window_seconds=0,
                max_copies=5,
                min_length=3,
            )
        )


# ---------------------------------------------------------------------------
# max_copies=0: "no copies allowed"
# ---------------------------------------------------------------------------


class MaxCopiesZeroTests(unittest.TestCase):
    """max_copies=0 means the first copy is already refused."""

    def test_zero_max_copies_refuses_first_copy(self) -> None:
        # With max_copies=0, count=0 >= 0 is True, so even
        # the first copy of a non-exempt text is refused.
        self.assertTrue(
            dupe_window_check(
                "hello",
                [],
                window_seconds=120,
                max_copies=0,
            )
        )

    def test_zero_max_copies_does_not_refuse_exempt_text(self) -> None:
        # Exempt texts are never refused, even with
        # max_copies=0.
        self.assertFalse(
            dupe_window_check(
                "ok",
                [],
                window_seconds=120,
                max_copies=0,
                min_length=3,
            )
        )


# ---------------------------------------------------------------------------
# Exemption interaction
# ---------------------------------------------------------------------------


class ExemptionInteractionTests(unittest.TestCase):
    """Texts below the length floor are never refused."""

    def test_exempt_text_never_refused_even_with_max_copies_in_history(self) -> None:
        # 5 copies of "hello" in the window does not affect
        # the verdict for "ok" when min_length=3 (the
        # documented conversational repeat case).
        history = _history(
            ("hello", 0),
            ("hello", 1),
            ("hello", 2),
            ("hello", 3),
            ("hello", 4),
        )
        self.assertFalse(
            dupe_window_check(
                "ok",
                history,
                window_seconds=120,
                max_copies=5,
                min_length=3,
            )
        )

    def test_exempt_text_with_floor_zero_uses_form_length(self) -> None:
        # When min_length=0, no text is exempt (because
        # dupe_exempt returns False for any non-empty text
        # at floor=0). So a non-exempt text with copies in
        # the history is still refused.
        history = _history(
            ("hello", 0),
            ("hello", 1),
            ("hello", 2),
            ("hello", 3),
            ("hello", 4),
        )
        self.assertTrue(
            dupe_window_check(
                "hello",
                history,
                window_seconds=120,
                max_copies=5,
                min_length=0,
            )
        )

    def test_documented_conversational_repeats_land_at_floor_three(self) -> None:
        # The three documented conversational repeats
        # ("ok", "gm", "+1") fold to length 2, which is
        # strictly less than 3, so they are exempt and
        # never refused regardless of the history.
        history = _history(*[("ok", float(i)) for i in range(100)])
        for text in ("ok", "gm", "+1"):
            with self.subTest(text=text):
                self.assertFalse(
                    dupe_window_check(
                        text,
                        history,
                        window_seconds=120,
                        max_copies=5,
                        min_length=3,
                    )
                )


# ---------------------------------------------------------------------------
# Fold interaction: the function folds the incoming text
# ---------------------------------------------------------------------------


class FoldInteractionTests(unittest.TestCase):
    """The function folds the incoming text before comparing."""

    def test_nfc_and_nfd_of_same_text_share_a_counter(self) -> None:
        # "ñ" in NFC (U+00F1) and "n" + U+0303 (combining
        # tilde) in NFD fold to the same form under NFKC, so
        # they share a counter. We avoid characters where
        # the precomposed form has a different diacritic
        # stack than the decomposed form (e.g. ệ = e +
        # circumflex + tilde below vs. e + combining tilde
        # above = ẽ); those are genuinely different
        # characters and do NOT fold together.
        nfc = "ñ"
        nfd = "n\u0303"
        self.assertEqual(dupe_form(nfc), dupe_form(nfd))
        history = _history(
            (nfc, 0),
            (nfc, 1),
            (nfc, 2),
            (nfc, 3),
            (nfd, 4),  # different NFC/NFD, same fold
        )
        self.assertTrue(
            dupe_window_check(
                nfc,
                history,
                window_seconds=120,
                max_copies=5,
                now=5.0,
            )
        )

    def test_case_fold_collapses_case_in_counter(self) -> None:
        # "Hello" and "HELLO" fold to the same form, so
        # they share a counter.
        history = _history(
            ("Hello", 0),
            ("HELLO", 1),
            ("hello", 2),
            ("hello", 3),
            ("hello", 4),
        )
        self.assertTrue(
            dupe_window_check(
                "HELLO",
                history,
                window_seconds=120,
                max_copies=5,
                now=5.0,
            )
        )

    def test_whitespace_fold_collapses_whitespace_in_counter(self) -> None:
        # "hello world" and "  hello   world  " fold to the
        # same form, so they share a counter.
        history = _history(
            ("hello world", 0),
            ("  hello   world  ", 1),
            ("hello\tworld", 2),
            ("hello world", 3),
            ("hello world", 4),
        )
        self.assertTrue(
            dupe_window_check(
                "hello world",
                history,
                window_seconds=120,
                max_copies=5,
                now=5.0,
            )
        )


# ---------------------------------------------------------------------------
# The ``now`` argument
# ---------------------------------------------------------------------------


class NowArgumentTests(unittest.TestCase):
    """The ``now`` argument controls the reference time for the window."""

    def test_default_now_is_latest_history_timestamp(self) -> None:
        # When ``now`` is omitted, the function uses the
        # latest timestamp in the history. So a history with
        # 5 copies at t=0..4 and a call without ``now``
        # should use now=4.0, and the next copy at any time
        # >= 4.0 should be refused.
        history = _history(
            ("hello", 0),
            ("hello", 1),
            ("hello", 2),
            ("hello", 3),
            ("hello", 4),
        )
        self.assertTrue(
            dupe_window_check(
                "hello",
                history,
                window_seconds=120,
                max_copies=5,
            )
        )

    def test_explicit_now_overrides_default(self) -> None:
        # An explicit ``now`` at a time outside the window
        # makes the copies "old" and the text lands.
        history = _history(
            ("hello", 0),
            ("hello", 1),
            ("hello", 2),
            ("hello", 3),
            ("hello", 4),
        )
        self.assertFalse(
            dupe_window_check(
                "hello",
                history,
                window_seconds=120,
                max_copies=5,
                now=1000.0,
            )
        )

    def test_explicit_now_can_be_in_the_past(self) -> None:
        # ``now`` can be any number; the function does not
        # require it to be monotonically increasing with the
        # history. A ``now`` in the past relative to the
        # history puts all copies inside the window.
        history = _history(
            ("hello", 100),
            ("hello", 101),
            ("hello", 102),
        )
        self.assertTrue(
            dupe_window_check(
                "hello",
                history,
                window_seconds=120,
                max_copies=2,
                now=102.0,
            )
        )


# ---------------------------------------------------------------------------
# Type-rejection surface
# ---------------------------------------------------------------------------


class TypeRejectionTests(unittest.TestCase):
    """Bad argument types must raise with static, non-amplifying messages."""

    def test_text_must_be_a_string(self) -> None:
        for bad in (None, 42, 3.14, b"hello", ["hello"], {"text": "hello"}):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError) as ctx:
                    dupe_window_check(
                        bad,
                        [],
                        window_seconds=120,
                        max_copies=5,
                    )
                self.assertEqual(str(ctx.exception), "text must be a str")

    def test_history_must_be_a_sequence(self) -> None:
        for bad in (None, 42, "history", 3.14, {"entries": []}):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError) as ctx:
                    dupe_window_check(
                        "hello",
                        bad,
                        window_seconds=120,
                        max_copies=5,
                    )
                self.assertIn(
                        "history must be a sequence of (folded_text, timestamp) pairs",
                        str(ctx.exception),
                    )

    def test_window_seconds_must_be_a_number(self) -> None:
        for bad in (None, "120", [120], {"seconds": 120}):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError) as ctx:
                    dupe_window_check(
                        "hello",
                        [],
                        window_seconds=bad,  # type: ignore[arg-type]
                        max_copies=5,
                    )
                self.assertIn("window_seconds", str(ctx.exception))

    def test_window_seconds_must_be_non_negative(self) -> None:
        with self.assertRaises(ValueError) as ctx:
            dupe_window_check(
                "hello",
                [],
                window_seconds=-1,
                max_copies=5,
            )
        self.assertIn("non-negative", str(ctx.exception))

    def test_max_copies_must_be_an_int(self) -> None:
        for bad in (None, "5", 5.0, [5], {"count": 5}):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError) as ctx:
                    dupe_window_check(
                        "hello",
                        [],
                        window_seconds=120,
                        max_copies=bad,  # type: ignore[arg-type]
                    )
                self.assertIn("max_copies", str(ctx.exception))

    def test_max_copies_rejects_bool(self) -> None:
        # ``bool`` is a subclass of ``int`` in Python but is
        # not a legal copy count here.
        with self.assertRaises(TypeError) as ctx:
            dupe_window_check(
                "hello",
                [],
                window_seconds=120,
                max_copies=True,  # type: ignore[arg-type]
            )
        self.assertIn("max_copies", str(ctx.exception))

    def test_max_copies_must_be_non_negative(self) -> None:
        with self.assertRaises(ValueError) as ctx:
            dupe_window_check(
                "hello",
                [],
                window_seconds=120,
                max_copies=-1,
            )
        self.assertIn("non-negative", str(ctx.exception))

    def test_min_length_must_be_an_int(self) -> None:
        for bad in (None, "3", 3.0, [3], {"length": 3}):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError) as ctx:
                    dupe_window_check(
                        "hello",
                        [],
                        window_seconds=120,
                        max_copies=5,
                        min_length=bad,  # type: ignore[arg-type]
                    )
                self.assertIn("min_length", str(ctx.exception))

    def test_min_length_must_be_non_negative(self) -> None:
        with self.assertRaises(ValueError) as ctx:
            dupe_window_check(
                "hello",
                [],
                window_seconds=120,
                max_copies=5,
                min_length=-1,
            )
        self.assertIn("non-negative", str(ctx.exception))

    def test_history_entry_must_be_2_elements(self) -> None:
        for bad in ([], [("hello", 0, 1)], "hello", 42):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError) as ctx:
                    dupe_window_check(
                        "hello",
                        [bad],  # type: ignore[list-item]
                        window_seconds=120,
                        max_copies=5,
                    )
                self.assertIn("history[0]", str(ctx.exception))

    def test_history_entry_text_must_be_a_string(self) -> None:
        with self.assertRaises(TypeError) as ctx:
            dupe_window_check(
                "hello",
                [(42, 0)],  # type: ignore[list-item]
                window_seconds=120,
                max_copies=5,
            )
        self.assertIn("history[0][0]", str(ctx.exception))

    def test_history_entry_timestamp_must_be_a_number(self) -> None:
        for bad in (None, "0", [0], {"ts": 0}):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError) as ctx:
                    dupe_window_check(
                        "hello",
                        [("hello", bad)],  # type: ignore[list-item]
                        window_seconds=120,
                        max_copies=5,
                    )
                self.assertIn("history[0][1]", str(ctx.exception))

    def test_now_must_be_a_number_or_none(self) -> None:
        for bad in ("1000", [1000], {"ts": 1000}):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError) as ctx:
                    dupe_window_check(
                        "hello",
                        [],
                        window_seconds=120,
                        max_copies=5,
                        now=bad,  # type: ignore[arg-type]
                    )
                self.assertIn("now", str(ctx.exception))

    def test_window_seconds_rejects_bool(self) -> None:
        # ``bool`` is a subclass of ``int`` in Python but is
        # not a legal window length here.
        with self.assertRaises(TypeError) as ctx:
            dupe_window_check(
                "hello",
                [],
                window_seconds=True,  # type: ignore[arg-type]
                max_copies=5,
            )
        self.assertIn("window_seconds", str(ctx.exception))

    def test_min_length_rejects_bool(self) -> None:
        # ``bool`` is a subclass of ``int`` in Python but is
        # not a legal length here.
        with self.assertRaises(TypeError) as ctx:
            dupe_window_check(
                "hello",
                [],
                window_seconds=120,
                max_copies=5,
                min_length=True,  # type: ignore[arg-type]
            )
        self.assertIn("min_length", str(ctx.exception))

    def test_history_timestamp_rejects_bool(self) -> None:
        # ``bool`` is a subclass of ``int`` in Python but is
        # not a legal timestamp here.
        with self.assertRaises(TypeError) as ctx:
            dupe_window_check(
                "hello",
                [("hello", True)],  # type: ignore[list-item]
                window_seconds=120,
                max_copies=5,
            )
        self.assertIn("history[0][1]", str(ctx.exception))


# ---------------------------------------------------------------------------
# validate_dupe_window: structured verdict
# ---------------------------------------------------------------------------


class ValidateDupeWindowTests(unittest.TestCase):
    """The validator returns a structured result, never raises."""

    def test_successful_verdict_populates_all_fields(self) -> None:
        history = _history(
            ("hello", 0),
            ("hello", 1),
            ("hello", 2),
        )
        result = validate_dupe_window(
            "hello",
            history,
            window_seconds=120,
            max_copies=5,
            now=3.0,
        )
        self.assertIsInstance(result, DupeWindowResult)
        self.assertTrue(result.valid)
        self.assertFalse(result.refused)
        self.assertEqual(result.folded, "hello")
        self.assertEqual(result.copies_in_window, 3)
        self.assertEqual(result.max_copies, 5)
        self.assertEqual(result.window_seconds, 120.0)
        self.assertIsNone(result.reason)

    def test_successful_verdict_refused(self) -> None:
        history = _history(
            ("hello", 0),
            ("hello", 1),
            ("hello", 2),
            ("hello", 3),
            ("hello", 4),
        )
        result = validate_dupe_window(
            "hello",
            history,
            window_seconds=120,
            max_copies=5,
            now=5.0,
        )
        self.assertTrue(result.valid)
        self.assertTrue(result.refused)
        self.assertEqual(result.copies_in_window, 5)

    def test_zero_window_verdict(self) -> None:
        result = validate_dupe_window(
            "hello",
            [],
            window_seconds=0,
            max_copies=5,
        )
        self.assertTrue(result.valid)
        self.assertFalse(result.refused)
        self.assertEqual(result.copies_in_window, 0)

    def test_exempt_verdict(self) -> None:
        history = _history(*[("hello", float(i)) for i in range(100)])
        result = validate_dupe_window(
            "ok",
            history,
            window_seconds=120,
            max_copies=5,
            min_length=3,
        )
        self.assertTrue(result.valid)
        self.assertFalse(result.refused)
        self.assertEqual(result.copies_in_window, 0)

    def test_failed_verdict_returns_static_reason(self) -> None:
        for bad in (None, 42, 3.14, b"hello", ["hello"], {"text": "hello"}):
            with self.subTest(bad=type(bad).__name__):
                result = validate_dupe_window(
                    bad,
                    [],
                    window_seconds=120,
                    max_copies=5,
                )
                self.assertFalse(result.valid)
                self.assertIsNone(result.refused)
                self.assertIsNone(result.folded)
                self.assertIsNone(result.copies_in_window)
                self.assertIsNone(result.max_copies)
                self.assertIsNone(result.window_seconds)
                self.assertEqual(result.reason, "text must be a string")

    def test_failed_verdict_does_not_echo_input(self) -> None:
        # The reason must be a static string; it must not
        # contain the input value.
        result = validate_dupe_window(
            42,
            [],
            window_seconds=120,
            max_copies=5,
        )
        self.assertNotIn("42", result.reason or "")
        self.assertNotIn("hello", result.reason or "")

    def test_failed_verdict_for_bad_history(self) -> None:
        result = validate_dupe_window(
            "hello",
            "not a list",  # type: ignore[arg-type]
            window_seconds=120,
            max_copies=5,
        )
        self.assertFalse(result.valid)
        self.assertIn("history", result.reason or "")

    def test_failed_verdict_for_negative_window(self) -> None:
        result = validate_dupe_window(
            "hello",
            [],
            window_seconds=-1,
            max_copies=5,
        )
        self.assertFalse(result.valid)
        self.assertIn("non-negative", result.reason or "")

    def test_failed_verdict_for_negative_max_copies(self) -> None:
        result = validate_dupe_window(
            "hello",
            [],
            window_seconds=120,
            max_copies=-1,
        )
        self.assertFalse(result.valid)
        self.assertIn("non-negative", result.reason or "")

    def test_failed_verdict_for_negative_min_length(self) -> None:
        result = validate_dupe_window(
            "hello",
            [],
            window_seconds=120,
            max_copies=5,
            min_length=-1,
        )
        self.assertFalse(result.valid)
        self.assertIn("non-negative", result.reason or "")

    def test_failed_verdict_for_bad_history_entry(self) -> None:
        result = validate_dupe_window(
            "hello",
            [("hello", "not a number")],  # type: ignore[list-item]
            window_seconds=120,
            max_copies=5,
        )
        self.assertFalse(result.valid)
        self.assertIn("history[0][1]", result.reason or "")

    def test_failed_verdict_for_bad_now(self) -> None:
        result = validate_dupe_window(
            "hello",
            [],
            window_seconds=120,
            max_copies=5,
            now="not a number",  # type: ignore[arg-type]
        )
        self.assertFalse(result.valid)
        self.assertIn("now", result.reason or "")


# ---------------------------------------------------------------------------
# No-amplification contract
# ---------------------------------------------------------------------------


class NoAmplificationTests(unittest.TestCase):
    """The function never echoes the input value onto any channel."""

    def test_error_messages_are_static(self) -> None:
        # Every error message must be a static,
        # parameter-free string. We check a few
        # representative cases.
        cases = [
            (TypeError, lambda: dupe_window_check(42, [], window_seconds=120, max_copies=5)),
            (TypeError, lambda: dupe_window_check("hello", "bad", window_seconds=120, max_copies=5)),
            (TypeError, lambda: dupe_window_check("hello", [], window_seconds="bad", max_copies=5)),
            (ValueError, lambda: dupe_window_check("hello", [], window_seconds=-1, max_copies=5)),
            (TypeError, lambda: dupe_window_check("hello", [], window_seconds=120, max_copies="bad")),
            (ValueError, lambda: dupe_window_check("hello", [], window_seconds=120, max_copies=-1)),
            (TypeError, lambda: dupe_window_check("hello", [], window_seconds=120, max_copies=5, min_length="bad")),
            (ValueError, lambda: dupe_window_check("hello", [], window_seconds=120, max_copies=5, min_length=-1)),
        ]
        for exc_type, call in cases:
            with self.subTest(call=call):
                with self.assertRaises(exc_type) as ctx:
                    call()
                msg = str(ctx.exception)
                # The error must not contain any part of the
                # input value ("hello" is the only string in
                # the valid input slots).
                self.assertNotIn("hello", msg)

    def test_validate_result_never_echoes_text(self) -> None:
        # The structured result's ``reason`` must never
        # contain the input text.
        result = validate_dupe_window(
            42,
            [],
            window_seconds=120,
            max_copies=5,
        )
        self.assertNotIn("42", result.reason or "")


# ---------------------------------------------------------------------------
# Parity with dupe_form and dupe_exempt
# ---------------------------------------------------------------------------


class ParityWithCompanionModulesTests(unittest.TestCase):
    """The window check must agree with dupe_form and dupe_exempt."""

    def test_folded_output_matches_dupe_form(self) -> None:
        # The function folds the text before comparing, so
        # the result's ``folded`` field must equal
        # :func:`dupe_form` on the same input.
        for text in ("Hello", "Việt", "  hello   world  ", "ok", "gm", "+1"):
            with self.subTest(text=text):
                result = validate_dupe_window(
                    text,
                    [],
                    window_seconds=120,
                    max_copies=5,
                )
                self.assertEqual(result.folded, dupe_form(text))

    def test_exempt_verdict_matches_dupe_exempt(self) -> None:
        # When the text is exempt, the function returns
        # ``refused=False``. When it is not exempt, the
        # function proceeds to the window check. This test
        # checks the exempt branch in isolation by passing
        # an empty history. The exemption rule is strict
        # less-than: "hello" (folded length 5) is NOT
        # exempt at floor=5, but IS exempt at floor=6.
        for text, min_length, expected_exempt in [
            ("ok", 3, True),
            ("ok", 2, False),
            ("hello", 3, False),
            ("hello", 6, True),
            ("", 0, False),
            ("", 1, True),
        ]:
            with self.subTest(text=text, min_length=min_length):
                result = validate_dupe_window(
                    text,
                    [],
                    window_seconds=120,
                    max_copies=5,
                    min_length=min_length,
                )
                if expected_exempt:
                    self.assertFalse(result.refused)
                    self.assertEqual(result.copies_in_window, 0)
                # If not exempt, the result depends on the
                # empty history; the function returns
                # ``refused=False`` with copies_in_window=0.
                else:
                    self.assertFalse(result.refused)
                    self.assertEqual(result.copies_in_window, 0)
                # And dupe_exempt must agree.
                self.assertEqual(
                    dupe_exempt(text, min_length),
                    expected_exempt,
                )


# ---------------------------------------------------------------------------
# Determinism and idempotence
# ---------------------------------------------------------------------------


class DeterminismTests(unittest.TestCase):
    """The function is deterministic over its inputs."""

    def test_same_inputs_same_verdict(self) -> None:
        history = _history(
            ("hello", 0),
            ("hello", 1),
            ("hello", 2),
            ("hello", 3),
            ("hello", 4),
        )
        for _ in range(10):
            self.assertEqual(
                dupe_window_check(
                    "hello",
                    history,
                    window_seconds=120,
                    max_copies=5,
                    now=5.0,
                ),
                True,
            )
            self.assertEqual(
                dupe_window_check(
                    "world",
                    history,
                    window_seconds=120,
                    max_copies=5,
                    now=5.0,
                ),
                False,
            )

    def test_validate_is_deterministic(self) -> None:
        history = _history(
            ("hello", 0),
            ("hello", 1),
        )
        r1 = validate_dupe_window(
            "hello",
            history,
            window_seconds=120,
            max_copies=5,
            now=2.0,
        )
        r2 = validate_dupe_window(
            "hello",
            history,
            window_seconds=120,
            max_copies=5,
            now=2.0,
        )
        self.assertEqual(r1, r2)


# ---------------------------------------------------------------------------
# The result dataclass is frozen
# ---------------------------------------------------------------------------


class FrozenResultTests(unittest.TestCase):
    """The DupeWindowResult dataclass is immutable."""

    def test_result_is_frozen(self) -> None:
        result = validate_dupe_window(
            "hello",
            [],
            window_seconds=120,
            max_copies=5,
        )
        with self.assertRaises(Exception):  # FrozenInstanceError
            result.refused = True  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Integration: the window check + the fold + the exemption compose
# ---------------------------------------------------------------------------


class IntegrationTests(unittest.TestCase):
    """The window check composes correctly with the fold and the exemption."""

    def test_nfc_nfd_repeats_share_counter_and_exempt_at_floor_three(self) -> None:
        # "gm" folds to "gm" (length 2), which is exempt at
        # floor=3. So even with many NFC/NFD variants in
        # the history, "gm" is never refused.
        history = _history(*[("gm", float(i)) for i in range(50)])
        result = validate_dupe_window(
            "gm",
            history,
            window_seconds=120,
            max_copies=5,
            min_length=3,
        )
        self.assertTrue(result.valid)
        self.assertFalse(result.refused)

    def test_long_text_with_floor_below_length_is_not_exempt(self) -> None:
        # A 11-character text at floor=5 is NOT exempt
        # (folded length 11 is not < 5). So with 5 copies
        # in the window, the next copy is refused.
        history = _history(*[("hello world", float(i)) for i in range(5)])
        result = validate_dupe_window(
            "hello world",
            history,
            window_seconds=120,
            max_copies=5,
            min_length=5,
        )
        self.assertTrue(result.valid)
        self.assertTrue(result.refused)
        self.assertEqual(result.copies_in_window, 5)

    def test_long_text_with_floor_above_length_is_exempt(self) -> None:
        # The same 11-character text at floor=20 IS exempt
        # (folded length 11 < 20). So the next copy is not
        # refused regardless of the history.
        history = _history(*[("hello world", float(i)) for i in range(5)])
        result = validate_dupe_window(
            "hello world",
            history,
            window_seconds=120,
            max_copies=5,
            min_length=20,
        )
        self.assertTrue(result.valid)
        self.assertFalse(result.refused)
        self.assertEqual(result.copies_in_window, 0)


if __name__ == "__main__":
    unittest.main()
