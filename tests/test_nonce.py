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
    NonceChecker,
    NonceCheckResult,
    NonceError,
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


if __name__ == "__main__":
    unittest.main()
