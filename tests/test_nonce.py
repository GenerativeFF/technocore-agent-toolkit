"""Unit tests for ``technocore_nonce``.
"""
from __future__ import annotations

import unittest
from pathlib import Path

import sys

# Allow ``python -m unittest`` from the repo root or any subdirectory.
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src.technocore_nonce import (
    DEFAULT_MIN_BITS,
    FLOAT53_BITS,
    FLOAT53_MAX_EXACT,
    NONCE_SAFETY_VERSION,
    NonceChecker,
    NonceCheckResult,
    NonceError,
    NonceSafetyResult,
    nonce_safety_assessment,
)  # noqa: E402


class NonceCheckerTests(unittest.TestCase):
    def setUp(self):
        self.checker = NonceChecker()
        self.did1 = "did:key:z6Mkkd6" # Example DID
        self.did2 = "did:key:z6Mkdd7" # Another example DID
        self.room1 = "lobby"
        self.room2 = "dev"

    def test_valid_first_nonce(self):
        result = self.checker.check_and_update(self.did1, self.room1, "1")
        self.assertTrue(result.valid)
        self.assertIsNone(result.reason)

    def test_strictly_increasing_nonce(self):
        self.checker.check_and_update(self.did1, self.room1, "100")
        result = self.checker.check_and_update(self.did1, self.room1, "101")
        self.assertTrue(result.valid)

    def test_replay_attack_same_nonce(self):
        self.checker.check_and_update(self.did1, self.room1, "50")
        result = self.checker.check_and_update(self.did1, self.room1, "50")
        self.assertFalse(result.valid)
        self.assertIn("not strictly greater", result.reason)

    def test_replay_attack_decreasing_nonce(self):
        self.checker.check_and_update(self.did1, self.room1, "70")
        result = self.checker.check_and_update(self.did1, self.room1, "69")
        self.assertFalse(result.valid)
        self.assertIn("not strictly greater", result.reason)

    def test_different_dids_independent_nonces(self):
        self.checker.check_and_update(self.did1, self.room1, "10")
        result = self.checker.check_and_update(self.did2, self.room1, "5")
        self.assertTrue(result.valid)
        self.checker.check_and_update(self.did2, self.room1, "11") # did2 can increase independently

    def test_different_rooms_independent_nonces(self):
        self.checker.check_and_update(self.did1, self.room1, "20")
        result = self.checker.check_and_update(self.did1, self.room2, "15")
        self.assertTrue(result.valid)
        self.checker.check_and_update(self.did1, self.room2, "21") # room2 can increase independently

    def test_invalid_nonce_format_non_digit(self):
        result = self.checker.check_and_update(self.did1, self.room1, "abc")
        self.assertFalse(result.valid)
        self.assertIn("1..19 decimal digits", result.reason)

    def test_invalid_nonce_format_too_long(self):
        result = self.checker.check_and_update(self.did1, self.room1, "1" * 20)
        self.assertFalse(result.valid)
        self.assertIn("1..19 decimal digits", result.reason)

    def test_invalid_nonce_format_empty(self):
        result = self.checker.check_and_update(self.did1, self.room1, "")
        self.assertFalse(result.valid)
        self.assertIn("1..19 decimal digits", result.reason)

    def test_nonce_zero(self):
        result = self.checker.check_and_update(self.did1, self.room1, "0")
        self.assertFalse(result.valid)
        self.assertIn("nonce must be positive", result.reason)

    def test_multiple_increments(self):
        self.checker.check_and_update(self.did1, self.room1, "10")
        self.checker.check_and_update(self.did1, self.room1, "15")
        result = self.checker.check_and_update(self.did1, self.room1, "20")
        self.assertTrue(result.valid)

    def test_interleaved_dids_and_rooms(self):
        self.checker.check_and_update(self.did1, self.room1, "1")
        self.checker.check_and_update(self.did2, self.room1, "1")
        self.checker.check_and_update(self.did1, self.room2, "1")
        self.checker.check_and_update(self.did1, self.room1, "2")
        self.checker.check_and_update(self.did2, self.room1, "2")
        self.checker.check_and_update(self.did1, self.room2, "2")

        # All should be valid at this point
        self.assertTrue(self.checker.check_and_update(self.did1, self.room1, "3").valid)
        self.assertTrue(self.checker.check_and_update(self.did2, self.room1, "3").valid)
        self.assertTrue(self.checker.check_and_update(self.did1, self.room2, "3").valid)

        # Replays should fail
        self.assertFalse(self.checker.check_and_update(self.did1, self.room1, "2").valid)
        self.assertFalse(self.checker.check_and_update(self.did2, self.room1, "1").valid)
        self.assertFalse(self.checker.check_and_update(self.did1, self.room2, "0").valid)


class NonceSafetyAssessmentTests(unittest.TestCase):
    """Tests for ``nonce_safety_assessment`` (v1.0.2)."""

    # ----- module-level constants -------------------------------------

    def test_float53_max_exact_is_two_to_53_minus_one(self):
        self.assertEqual(FLOAT53_MAX_EXACT, (1 << 53) - 1)
        # Spot-check: 2**53 - 1 = 9_007_199_254_740_991, which has
        # 16 digits and is below 10**16.
        self.assertEqual(FLOAT53_MAX_EXACT, 9_007_199_254_740_991)
        self.assertLess(10**15, FLOAT53_MAX_EXACT)  # 10^15 = 1e15
        self.assertGreater(10**16, FLOAT53_MAX_EXACT)  # 10^16 = 1e16

    def test_float53_bits_is_53(self):
        self.assertEqual(FLOAT53_BITS, 53)

    def test_default_min_bits_is_32(self):
        self.assertEqual(DEFAULT_MIN_BITS, 32)

    def test_safety_version_is_one(self):
        self.assertEqual(NONCE_SAFETY_VERSION, 1)

    # ----- shape validation (parity with NonceChecker) ----------------

    def test_valid_single_digit_nonce(self):
        result = nonce_safety_assessment("1")
        self.assertIsInstance(result, NonceSafetyResult)
        self.assertTrue(result.valid)
        self.assertIsNone(result.reason)
        self.assertEqual(result.bit_length, 1)
        self.assertTrue(result.fits_in_float53)
        self.assertTrue(result.entropy_warning)  # 1 < 32

    def test_valid_max_digit_nonce(self):
        result = nonce_safety_assessment("9" * 19)
        self.assertTrue(result.valid)
        self.assertEqual(result.bit_length, (10**19 - 1).bit_length())
        # 19 nines is well above 2**53.
        self.assertFalse(result.fits_in_float53)
        # And well above 32 bits.
        self.assertFalse(result.entropy_warning)

    def test_invalid_empty_nonce(self):
        result = nonce_safety_assessment("")
        self.assertFalse(result.valid)
        self.assertIn("1..19 decimal digits", result.reason)

    def test_invalid_too_long_nonce(self):
        result = nonce_safety_assessment("1" * 20)
        self.assertFalse(result.valid)
        self.assertIn("1..19 decimal digits", result.reason)

    def test_invalid_nonnumeric_nonce(self):
        result = nonce_safety_assessment("abc")
        self.assertFalse(result.valid)
        self.assertIn("1..19 decimal digits", result.reason)

    def test_invalid_zero_nonce(self):
        result = nonce_safety_assessment("0")
        self.assertFalse(result.valid)
        self.assertIn("nonce must be positive", result.reason)

    def test_invalid_unicode_digit_rejected(self):
        # ``str.isdigit()`` accepts some non-ASCII digits; the
        # protocol is decimal (0-9), so they must be rejected.
        # U+0660 is ARABIC-INDIC DIGIT ZERO.
        result = nonce_safety_assessment("\u06601")
        self.assertFalse(result.valid)
        self.assertIn("1..19 decimal digits", result.reason)

    def test_invalid_input_type_raises(self):
        with self.assertRaises(TypeError):
            nonce_safety_assessment(123)  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            nonce_safety_assessment(None)  # type: ignore[arg-type]

    # ----- float53 boundary -------------------------------------------

    def test_float53_max_exact_fits(self):
        result = nonce_safety_assessment(str(FLOAT53_MAX_EXACT))
        self.assertTrue(result.valid)
        self.assertTrue(result.fits_in_float53)

    def test_float53_max_plus_one_does_not_fit(self):
        # The smallest integer that loses precision in a double.
        result = nonce_safety_assessment(str(FLOAT53_MAX_EXACT + 1))
        self.assertTrue(result.valid)
        self.assertFalse(result.fits_in_float53)

    def test_15_digit_max_fits_in_float53(self):
        # 999_999_999_999_999 has 15 nines; well under 2**53.
        result = nonce_safety_assessment("9" * 15)
        self.assertTrue(result.valid)
        self.assertTrue(result.fits_in_float53)

    def test_16_digit_nonce_does_not_fit(self):
        # FLOAT53_MAX_EXACT + 1 is the smallest integer that does
        # not fit exactly in an IEEE 754 double; it is also the
        # smallest 16-digit nonce that does not fit.
        result = nonce_safety_assessment(str(FLOAT53_MAX_EXACT + 1))
        self.assertTrue(result.valid)
        self.assertFalse(result.fits_in_float53)

    # ----- entropy / bit length ---------------------------------------

    def test_bit_length_known_values(self):
        cases = [
            ("1", 1),
            ("2", 2),
            ("3", 2),  # 3 = 0b11
            ("4", 3),
            ("255", 8),
            ("256", 9),
            ("1023", 10),
            ("1024", 11),
        ]
        for nonce_str, expected_bits in cases:
            with self.subTest(nonce_str=nonce_str):
                result = nonce_safety_assessment(nonce_str)
                self.assertTrue(result.valid)
                self.assertEqual(result.bit_length, expected_bits)

    def test_entropy_warning_below_default(self):
        # 2**31 - 1 has 31 bits, below the 32-bit default threshold.
        result = nonce_safety_assessment(str((1 << 31) - 1))
        self.assertTrue(result.valid)
        self.assertEqual(result.bit_length, 31)
        self.assertTrue(result.entropy_warning)

    def test_entropy_warning_at_threshold(self):
        # 2**31 has exactly 32 bits when represented as ``int``
        # (2**31 = 0x80000000, which needs 32 significant bits);
        # not below 32, so no warning.
        result = nonce_safety_assessment(str(1 << 31))
        self.assertTrue(result.valid)
        self.assertEqual(result.bit_length, 32)
        self.assertFalse(result.entropy_warning)

    def test_entropy_warning_custom_threshold(self):
        # A 16-bit nonce is fine for a low-stakes room; raise the
        # threshold and the warning flips off.
        result = nonce_safety_assessment("65535")  # 2**16 - 1
        self.assertTrue(result.valid)
        self.assertEqual(result.bit_length, 16)
        self.assertTrue(result.entropy_warning)  # below 32
        # Raise the threshold to 8; 16 >= 8, no warning.
        result = nonce_safety_assessment("65535", min_bits=8)
        self.assertTrue(result.valid)
        self.assertFalse(result.entropy_warning)
        # Lower the threshold to 64; 16 < 64, warning returns.
        result = nonce_safety_assessment("65535", min_bits=64)
        self.assertTrue(result.valid)
        self.assertTrue(result.entropy_warning)

    def test_invalid_min_bits_raises(self):
        with self.assertRaises(TypeError):
            nonce_safety_assessment("1", min_bits=32.0)  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            nonce_safety_assessment("1", min_bits=True)  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            nonce_safety_assessment("1", min_bits=0)
        with self.assertRaises(ValueError):
            nonce_safety_assessment("1", min_bits=-1)

    # ----- invariants across the shape boundary -----------------------

    def test_invalid_nonce_zero_populated_fields(self):
        result = nonce_safety_assessment("0")
        self.assertFalse(result.valid)
        # Structured fields are only meaningful when valid; the
        # implementation still emits safe defaults so a caller that
        # ignores ``valid`` cannot accidentally read stale state.
        self.assertEqual(result.bit_length, 0)
        self.assertTrue(result.fits_in_float53)
        self.assertFalse(result.entropy_warning)
        self.assertEqual(result.version, NONCE_SAFETY_VERSION)

    def test_result_is_immutable(self):
        result = nonce_safety_assessment("12345")
        with self.assertRaises(Exception):
            result.valid = False  # type: ignore[misc]

    def test_parity_with_nonce_checker_shape(self):
        # The shape verdict of the safety assessment must match
        # the shape verdict of the ``NonceChecker`` for every
        # well-formed and malformed input. The ``NonceChecker``
        # additionally enforces ordering; that is out of scope
        # for the safety assessment.
        checker = NonceChecker()
        did = "did:key:z6Mkparity"
        room = "parity"
        for nonce_str in ["", "0", "abc", "1" * 20, "0", "1", "5", "10"]:
            with self.subTest(nonce_str=nonce_str):
                safety = nonce_safety_assessment(nonce_str)
                check = checker.check_and_update(did, room, nonce_str)
                self.assertEqual(safety.valid, check.valid)


if __name__ == "__main__":
    unittest.main()
