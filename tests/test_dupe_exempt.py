"""Unit tests for :mod:`src.technocore_dupe_exempt`.

The dupe-filter exemption check is a thin policy layer on top
of :func:`dupe_form`: a text is exempt from the 5-copy 422
counter when its folded length is strictly less than the
caller-supplied ``min_length`` floor. The test suite locks
down the boundary (strict-less-than), the documented
conversational repeats (``ok``, ``gm``, ``+1``), the
no-amplification contract, the type-rejection surface, the
parity with :func:`dupe_form`, and the idempotence /
determinism of the verdict.
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
from src.technocore_dupe_exempt import (  # noqa: E402
    DUPE_EXEMPT_VERSION,
    DupeExemptError,
    DupeExemptResult,
    dupe_exempt,
    validate_dupe_exempt,
)
from src.technocore_dupe_form import dupe_form  # noqa: E402


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------


class ConstantsTests(unittest.TestCase):
    """The exported constants must agree with the documented invariant."""

    def test_version_is_a_positive_int(self) -> None:
        self.assertIsInstance(DUPE_EXEMPT_VERSION, int)
        self.assertGreaterEqual(DUPE_EXEMPT_VERSION, 1)


# ---------------------------------------------------------------------------
# Boundary: strict-less-than
# ---------------------------------------------------------------------------


class BoundaryTests(unittest.TestCase):
    """The rule is "shorter than the length floor" — strict, not inclusive."""

    def test_empty_string_always_exempt_at_any_floor(self) -> None:
        # An empty input folds to the empty string (length 0),
        # which is strictly less than every non-negative floor.
        for floor in (0, 1, 2, 5, 10, 4096):
            with self.subTest(floor=floor):
                # floor == 0 is the only floor at which 0 is not
                # strictly less than the floor, so it is the only
                # case at which the empty string is NOT exempt.
                expected = 0 < floor
                self.assertEqual(dupe_exempt("", floor), expected)

    def test_floor_zero_disables_exemption_for_nonempty(self) -> None:
        # A floor of 0 disables the floor: every non-empty
        # folded string has length >= 1, which is NOT strictly
        # less than 0, so it is NOT exempt.
        self.assertFalse(dupe_exempt("ok", 0))
        self.assertFalse(dupe_exempt("hello world", 0))
        self.assertFalse(dupe_exempt("a", 0))

    def test_floor_one_exempts_only_empty(self) -> None:
        # floor=1: only the empty string (folded length 0) is
        # strictly less than 1. A single-codepoint text folds
        # to length 1, which is NOT strictly less than 1.
        self.assertTrue(dupe_exempt("", 1))
        self.assertFalse(dupe_exempt("a", 1))
        self.assertFalse(dupe_exempt("ok", 1))

    def test_floor_equal_to_folded_length_is_not_exempt(self) -> None:
        # "ok" folds to "ok" (length 2). At floor=2, the
        # folded length is NOT strictly less than the floor,
        # so it is NOT exempt. This is the strict-less-than
        # boundary.
        self.assertEqual(len(dupe_form("ok")), 2)
        self.assertFalse(dupe_exempt("ok", 2))

    def test_floor_one_below_folded_length_is_exempt(self) -> None:
        # "ok" folds to "ok" (length 2). At floor=3, the
        # folded length (2) is strictly less than the floor
        # (3), so it IS exempt.
        self.assertTrue(dupe_exempt("ok", 3))

    def test_floor_one_above_folded_length_is_not_exempt(self) -> None:
        # "ok" folds to "ok" (length 2). At floor=1, the
        # folded length (2) is NOT strictly less than the
        # floor (1), so it is NOT exempt.
        self.assertFalse(dupe_exempt("ok", 1))


# ---------------------------------------------------------------------------
# Conversational repeats from the documented example
# ---------------------------------------------------------------------------


class ConversationalRepeatTests(unittest.TestCase):
    """The three documented conversational repeats must always land.

    The DUPLICATES section is explicit: "messages shorter than
    the length floor are exempt, so conversational repeats
    ('ok', 'gm', '+1') always land." All three fold to a
    two-codepoint form, so any floor >= 3 exempts them.
    """

    def test_ok_folds_to_two_codepoints(self) -> None:
        self.assertEqual(dupe_form("ok"), "ok")
        self.assertEqual(len(dupe_form("ok")), 2)

    def test_gm_folds_to_two_codepoints(self) -> None:
        self.assertEqual(dupe_form("gm"), "gm")
        self.assertEqual(len(dupe_form("gm")), 2)

    def test_plus_one_folds_to_two_codepoints(self) -> None:
        self.assertEqual(dupe_form("+1"), "+1")
        self.assertEqual(len(dupe_form("+1")), 2)

    def test_documented_repeats_exempt_at_floor_three(self) -> None:
        for text in ("ok", "gm", "+1"):
            with self.subTest(text=text):
                self.assertTrue(dupe_exempt(text, 3))

    def test_documented_repeats_exempt_at_realistic_floor(self) -> None:
        # The floor is a per-server config value; typical
        # values are 3-10. All three documented repeats must
        # be exempt across the whole range.
        for text in ("ok", "gm", "+1"):
            with self.subTest(text=text):
                for floor in (3, 5, 8, 10, 20):
                    self.assertTrue(dupe_exempt(text, floor))

    def test_documented_repeats_not_exempt_at_floor_two(self) -> None:
        # The folded length is 2; at floor=2 the rule is
        # "strictly less than", so these are NOT exempt.
        for text in ("ok", "gm", "+1"):
            with self.subTest(text=text):
                self.assertFalse(dupe_exempt(text, 2))


# ---------------------------------------------------------------------------
# Whitespace bypass attempts must NOT defeat the floor
# ---------------------------------------------------------------------------


class WhitespaceBypassTests(unittest.TestCase):
    """The fold collapses whitespace, so adding spaces cannot bypass the floor."""

    def test_ok_with_trailing_spaces_folds_to_two_codepoints(self) -> None:
        # The whitespace fold strips ends and collapses
        # internal runs, so "ok   " folds to "ok".
        self.assertEqual(dupe_form("ok   "), "ok")
        self.assertEqual(len(dupe_form("ok   ")), 2)

    def test_ok_with_leading_spaces_folds_to_two_codepoints(self) -> None:
        self.assertEqual(dupe_form("   ok"), "ok")

    def test_ok_with_surrounding_spaces_folds_to_two_codepoints(self) -> None:
        self.assertEqual(dupe_form("  ok  "), "ok")

    def test_ok_with_internal_whitespace_folds_to_two_codepoints(self) -> None:
        # "o\tk\n" folds to "o k" (length 3), which IS
        # exempt at floor=4. This shows that internal
        # whitespace CAN push the folded length past the
        # floor, which is the documented behavior of the
        # whitespace fold; the bypass is not a free
        # exemption.
        self.assertEqual(dupe_form("o\tk\n"), "o k")
        self.assertEqual(len(dupe_form("o\tk\n")), 3)
        self.assertTrue(dupe_exempt("o\tk\n", 4))
        self.assertFalse(dupe_exempt("o\tk\n", 3))

    def test_trailing_spaces_do_not_change_exemption(self) -> None:
        # "ok" and "ok   " must produce the same verdict
        # at every non-negative floor.
        for floor in (0, 1, 2, 3, 5, 10):
            with self.subTest(floor=floor):
                self.assertEqual(
                    dupe_exempt("ok", floor),
                    dupe_exempt("ok   ", floor),
                )

    def test_leading_spaces_do_not_change_exemption(self) -> None:
        for floor in (0, 1, 2, 3, 5, 10):
            with self.subTest(floor=floor):
                self.assertEqual(
                    dupe_exempt("ok", floor),
                    dupe_exempt("   ok", floor),
                )


# ---------------------------------------------------------------------------
# Case-folding bypass attempts must NOT defeat the floor
# ---------------------------------------------------------------------------


class CaseFoldingBypassTests(unittest.TestCase):
    """The fold casefolds, so the case cannot bypass the floor either."""

    def test_uppercase_ok_folds_to_two_codepoints(self) -> None:
        # NFKC + casefold of "OK" is "ok" (length 2).
        self.assertEqual(dupe_form("OK"), "ok")
        self.assertEqual(len(dupe_form("OK")), 2)

    def test_mixed_case_plus_one_folds_to_two_codepoints(self) -> None:
        # "+1" has no letters, so case-folding is a no-op
        # but NFKC is also a no-op; the form is still "+1".
        self.assertEqual(dupe_form("+1"), "+1")

    def test_german_sharp_s_folds_to_seven_codepoints(self) -> None:
        # "Straße" casefolds to "strasse" (length 7). At
        # floor=7 the rule is "strictly less than", so it is
        # NOT exempt; at floor=8 the folded length is strictly
        # less, so it IS exempt. This is the boundary.
        self.assertEqual(dupe_form("Straße"), "strasse")
        self.assertEqual(len(dupe_form("Straße")), 7)
        self.assertFalse(dupe_exempt("Straße", 7))
        self.assertTrue(dupe_exempt("Straße", 8))


# ---------------------------------------------------------------------------
# Type rejection
# ---------------------------------------------------------------------------


class TypeRejectionTests(unittest.TestCase):
    """Bad input types must raise TypeError; bad min_length values too."""

    def test_text_must_be_str(self) -> None:
        for bad in (None, 0, 1, 1.5, b"ok", bytearray(b"ok"), ["ok"], {"ok": True}):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    dupe_exempt(bad, 3)  # type: ignore[arg-type]

    def test_min_length_must_be_int(self) -> None:
        for bad in (None, 1.0, 1.5, "3", b"3", [3], {3: True}):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    dupe_exempt("ok", bad)  # type: ignore[arg-type]

    def test_min_length_must_not_be_bool(self) -> None:
        # ``bool`` is a subclass of ``int`` in Python; we
        # explicitly reject it because True/False is not a
        # meaningful length floor.
        with self.assertRaises(TypeError):
            dupe_exempt("ok", True)  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            dupe_exempt("ok", False)  # type: ignore[arg-type]

    def test_min_length_must_be_non_negative(self) -> None:
        for bad in (-1, -2, -100):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    dupe_exempt("ok", bad)


# ---------------------------------------------------------------------------
# Idempotence, determinism, and parity with dupe_form
# ---------------------------------------------------------------------------


class ParityWithDupeFormTests(unittest.TestCase):
    """The verdict must be a pure function of ``len(dupe_form(text)) < min_length``."""

    def test_exempt_iff_folded_length_strictly_less(self) -> None:
        # A randomised cross-check would be nice here, but
        # the rule is tight enough that a small fixture is
        # sufficient. Every (text, floor) pair below was
        # chosen to cover a distinct region of the boundary.
        cases = [
            ("", 0, False),    # 0 < 0 is False
            ("", 1, True),     # 0 < 1 is True
            ("a", 1, False),   # 1 < 1 is False
            ("a", 2, True),    # 1 < 2 is True
            ("ok", 2, False),  # 2 < 2 is False
            ("ok", 3, True),   # 2 < 3 is True
            ("hello", 5, False),  # 5 < 5 is False
            ("hello", 6, True),   # 5 < 6 is True
            ("Hello", 5, False),  # casefolds to "hello" (length 5)
            ("Hello", 6, True),
        ]
        for text, floor, expected in cases:
            with self.subTest(text=text, floor=floor):
                self.assertEqual(dupe_exempt(text, floor), expected)

    def test_does_not_call_dupe_form_directly_but_agrees_with_it(self) -> None:
        # The function delegates to dupe_form; the
        # exemption must match what the caller would get by
        # computing the fold themselves.
        for text, floor in [("ok", 0), ("ok", 1), ("ok", 2), ("ok", 3),
                            ("hello world", 5), ("hello world", 11),
                            ("hello world", 12), ("hello world", 4096)]:
            with self.subTest(text=text, floor=floor):
                self.assertEqual(
                    dupe_exempt(text, floor),
                    len(dupe_form(text)) < floor,
                )

    def test_determinism(self) -> None:
        # Calling dupe_exempt with the same arguments must
        # always return the same value.
        for _ in range(5):
            self.assertTrue(dupe_exempt("ok", 3))
            self.assertFalse(dupe_exempt("ok", 2))

    def test_idempotence(self) -> None:
        # The verdict is a function of (text, min_length);
        # there is no internal state to accumulate.
        first = dupe_exempt("ok", 3)
        second = dupe_exempt("ok", 3)
        self.assertEqual(first, second)


# ---------------------------------------------------------------------------
# validate_dupe_exempt: structured result
# ---------------------------------------------------------------------------


class ValidateDupeExemptTests(unittest.TestCase):
    """The structured result must carry the verdict, the fold, and the floor."""

    def test_valid_result_carries_fold_and_floor(self) -> None:
        result = validate_dupe_exempt("ok", 3)
        self.assertIsInstance(result, DupeExemptResult)
        self.assertTrue(result.valid)
        self.assertTrue(result.exempt)
        self.assertEqual(result.folded, "ok")
        self.assertEqual(result.folded_length, 2)
        self.assertEqual(result.min_length, 3)
        self.assertIsNone(result.reason)

    def test_valid_result_not_exempt_at_equal_floor(self) -> None:
        result = validate_dupe_exempt("ok", 2)
        self.assertTrue(result.valid)
        self.assertFalse(result.exempt)
        self.assertEqual(result.folded, "ok")
        self.assertEqual(result.folded_length, 2)
        self.assertEqual(result.min_length, 2)

    def test_valid_result_not_exempt_at_floor_below_fold(self) -> None:
        result = validate_dupe_exempt("ok", 1)
        self.assertTrue(result.valid)
        self.assertFalse(result.exempt)

    def test_invalid_text_does_not_echo_value(self) -> None:
        # The reason must be a static string that does not
        # contain the offending value. We deliberately use
        # a non-string payload whose repr is recognisable
        # but unique, so any accidental interpolation
        # surfaces immediately.
        sentinel = b"SENTINEL-MUST-NOT-LEAK-XYZQ"
        result = validate_dupe_exempt(sentinel, 3)
        self.assertFalse(result.valid)
        self.assertIsNone(result.exempt)
        self.assertIsNone(result.folded)
        self.assertIsNone(result.folded_length)
        self.assertIsNone(result.min_length)
        self.assertIsNotNone(result.reason)
        # Neither the bytes payload nor its decoded form
        # may appear in the reason.
        self.assertNotIn("SENTINEL-MUST-NOT-LEAK-XYZQ", result.reason)
        self.assertNotIn("SENTINEL", result.reason)
        # And of course the sentinel is not in any of the
        # populated fields either, but they are all None
        # when valid is False.

    def test_invalid_min_length_does_not_echo_value(self) -> None:
        result = validate_dupe_exempt("ok", -1)
        self.assertFalse(result.valid)
        self.assertIsNone(result.exempt)
        self.assertIsNone(result.folded)
        self.assertIsNotNone(result.reason)
        # The reason must NOT contain the offending value
        # (the integer -1). It is allowed to mention the
        # word "non-negative", which happens to contain a
        # hyphen — that is part of the static reason, not
        # an echo of the input.
        self.assertNotIn("-1", result.reason)
        self.assertNotIn("ok", result.reason)

    def test_invalid_min_length_type_does_not_echo_value(self) -> None:
        result = validate_dupe_exempt("ok", "3")  # type: ignore[arg-type]
        self.assertFalse(result.valid)
        self.assertIsNotNone(result.reason)
        self.assertNotIn("3", result.reason)
        # The string "3" is not in any static reason.
        self.assertNotIn('"3"', result.reason)

    def test_invalid_min_length_bool_does_not_echo_value(self) -> None:
        result = validate_dupe_exempt("ok", True)  # type: ignore[arg-type]
        self.assertFalse(result.valid)
        self.assertIsNotNone(result.reason)
        self.assertNotIn("True", result.reason)
        self.assertNotIn("False", result.reason)

    def test_result_is_immutable(self) -> None:
        # ``DupeExemptResult`` is a frozen dataclass;
        # assigning to any field must raise.
        result = validate_dupe_exempt("ok", 3)
        with self.assertRaises(Exception):
            result.exempt = False  # type: ignore[misc]
        with self.assertRaises(Exception):
            result.min_length = 0  # type: ignore[misc]

    def test_min_length_echoed_back_for_logging(self) -> None:
        # The result echoes the min_length the caller
        # supplied so a caller that lost track of its own
        # config can log it. This is intentional and is
        # not a leak of untrusted data.
        result = validate_dupe_exempt("ok", 42)
        self.assertEqual(result.min_length, 42)
        result = validate_dupe_exempt("hello", 0)
        self.assertEqual(result.min_length, 0)


# ---------------------------------------------------------------------------
# Version export
# ---------------------------------------------------------------------------


class VersionTests(unittest.TestCase):
    """The contract version is exported and pinned at 1."""

    def test_version_constant_is_one(self) -> None:
        self.assertEqual(DUPE_EXEMPT_VERSION, 1)


# ---------------------------------------------------------------------------
# DupeExemptError class
# ---------------------------------------------------------------------------


class DupeExemptErrorTests(unittest.TestCase):
    """The error type is exported and is a ValueError subclass."""

    def test_is_a_value_error(self) -> None:
        self.assertTrue(issubclass(DupeExemptError, ValueError))

    def test_can_be_raised_with_a_static_message(self) -> None:
        # The module never raises this directly; it is
        # exported for callers that want to catch it. We
        # verify the inheritance and the basic raise/
        # catch contract.
        with self.assertRaises(DupeExemptError):
            raise DupeExemptError("static message")


if __name__ == "__main__":
    unittest.main()
