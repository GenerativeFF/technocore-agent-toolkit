"""Unit tests for ``technocore_sweep``.

The sweep is the single-pass character substitution that Technocore
applies to ``text`` before storing and signing. Tests cover:

* identity: clean text is preserved exactly;
* every documented sweep range, with explicit codepoints at the
  boundaries (first, last, and one just past the last);
* codepoints that must be **preserved** even though they sit near
  the sweep ranges (U+0020, U+00A0, U+2010, U+202F, etc.);
* length accounting and ``length_delta``;
* replaced-codepoint set semantics (each distinct codepoint
  reported once, no extras);
* idempotence: ``sweep(sweep(x)) == sweep(x)``;
* determinism;
* strict input validation (non-``str`` raises ``SweepError``);
* parity with ``technocore_verify.sweep`` and with the supplied
  Hermes client sweep, so future code can rely on a single source
  of truth.

The sweep is a pure function. There is no network I/O, no
subprocess, no decoding.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src.technocore_sweep import (  # noqa: E402
    SWEEP_RANGES,
    SWEEP_REPLACEMENT,
    SweepError,
    SweepReport,
    expected_replacements,
    sweep,
    sweep_report,
)
from src.technocore_verify import sweep as verifier_sweep  # noqa: E402


# ---------------------------------------------------------------------------
# Constants / structure
# ---------------------------------------------------------------------------


class StructureTests(unittest.TestCase):
    def test_sweep_ranges_are_inclusive_lower_exclusive_upper(self):
        for lo, hi in SWEEP_RANGES:
            self.assertLess(lo, hi, f"empty range {(lo, hi)}")
            self.assertGreaterEqual(lo, 0)

    def test_four_documented_ranges(self):
        # The protocol notes document exactly four ranges. Adding or
        # removing one is a breaking change that must be reflected in
        # ``docs/protocol-notes.md`` and in CONTRIBUTIONS.md.
        self.assertEqual(
            SWEEP_RANGES,
            (
                (0x0000, 0x0020),  # C0 controls (NUL through unit-separator)
                (0x007F, 0x00A0),  # DEL + C1 controls
                (0x200B, 0x2010),  # zero-width and friends
                (0x202A, 0x202F),  # bidi embedding/isolate/override
            ),
        )

    def test_replacement_is_space(self):
        self.assertEqual(SWEEP_REPLACEMENT, " ")
        self.assertEqual(ord(SWEEP_REPLACEMENT), 0x20)


# ---------------------------------------------------------------------------
# Identity / happy path
# ---------------------------------------------------------------------------


class IdentityTests(unittest.TestCase):
    def test_empty_string(self):
        self.assertEqual(sweep(""), "")

    def test_ascii_preserved(self):
        self.assertEqual(sweep("hello world"), "hello world")

    def test_printable_preserved(self):
        # The sweep must not touch the regular printable range.
        text = "abcXYZ012-_.:!?/'\"`~@#$%^&*()+=[]{}<>,;\\|"
        self.assertEqual(sweep(text), text)

    def test_nbsp_preserved(self):
        # U+00A0 is just past the C1 range and must be preserved.
        self.assertEqual(sweep("a\u00A0b"), "a\u00A0b")

    def test_space_preserved(self):
        # U+0020 is the *replacement*, never a sweep target.
        self.assertEqual(sweep("   "), "   ")

    def test_cjk_preserved(self):
        # CJK, hiragana, katakana, and fullwidth forms must all be
        # preserved byte-for-byte. The sweep does no normalization.
        for sample in (
            "你好,世界",
            "こんにちは",
            "カタカナ",
            "ＡＢＣ１２３",
            "한글",
        ):
            self.assertEqual(sweep(sample), sample, f"failed for {sample!r}")

    def test_emoji_preserved(self):
        # Emoji live in high planes and must never be touched.
        for sample in ("👋🌍🚀", "café 🧋", "🪪"):
            self.assertEqual(sweep(sample), sample, f"failed for {sample!r}")

    def test_combining_marks_preserved(self):
        # Combining acute and other U+0300..U+036F marks are not in
        # the sweep ranges; they are part of the message text.
        self.assertEqual(sweep("e\u0301"), "e\u0301")  # "é" decomposed

    def test_ligatures_preserved(self):
        # Latin ligatures live in the Latin Extended-A block and
        # are not sweep targets.
        for sample in ("\u00C6", "\u0153", "\u1E9E"):
            self.assertEqual(sweep(sample), sample)


# ---------------------------------------------------------------------------
# Per-range coverage
# ---------------------------------------------------------------------------


class RangeCoverageTests(unittest.TestCase):
    """For each documented range, prove every codepoint is replaced."""

    def test_c0_range_full(self):
        for cp in range(0x0000, 0x0020):
            ch = chr(cp)
            self.assertEqual(sweep(f"a{ch}b"), "a b", f"cp=U+{cp:04X}")

    def test_c1_and_del_range_full(self):
        for cp in range(0x007F, 0x00A0):
            ch = chr(cp)
            self.assertEqual(sweep(f"a{ch}b"), "a b", f"cp=U+{cp:04X}")

    def test_zero_width_range_full(self):
        for cp in range(0x200B, 0x2010):
            ch = chr(cp)
            self.assertEqual(sweep(f"a{ch}b"), "a b", f"cp=U+{cp:04X}")

    def test_bidi_range_full(self):
        for cp in range(0x202A, 0x202F):
            ch = chr(cp)
            self.assertEqual(sweep(f"a{ch}b"), "a b", f"cp=U+{cp:04X}")

    def test_boundary_codepoints_outside_ranges(self):
        # Codepoints just past each range's exclusive upper bound.
        for cp in (0x0020, 0x00A0, 0x2010, 0x202F):
            ch = chr(cp)
            self.assertEqual(sweep(f"a{ch}b"), f"a{ch}b",
                             f"cp=U+{cp:04X} should be preserved")

    def test_one_past_upper_is_preserved(self):
        # Codepoints one past the exclusive upper bound must be
        # preserved. This protects against an off-by-one in a future
        # refactor.
        for upper in (0x0020, 0x00A0, 0x2010, 0x202F):
            ch = chr(upper)
            self.assertEqual(sweep(ch), ch, f"U+{upper:04X} should be preserved")

    def test_first_in_each_range_replaced(self):
        for lo, _ in SWEEP_RANGES:
            ch = chr(lo)
            self.assertEqual(sweep(ch), " ", f"first of range @U+{lo:04X}")


# ---------------------------------------------------------------------------
# Length, ordering, idempotence, determinism
# ---------------------------------------------------------------------------


class InvariantTests(unittest.TestCase):
    def test_length_preserved(self):
        for s in ("", "abc", "a\u0000b", "\u200B\u200C", "héllo 👋"):
            out = sweep(s)
            self.assertEqual(len(out), len(s), f"len changed for {s!r}")

    def test_no_collapsing_of_runs(self):
        # The sweep does not collapse consecutive matches into a
        # single space. The protocol is a 1:1 substitution.
        s = "\u0000\u0001\u0002"
        self.assertEqual(sweep(s), "   ")

    def test_no_trimming(self):
        # Leading/trailing whitespace and other edges are not trimmed.
        s = " \u200B abc \u0007 "
        self.assertEqual(sweep(s), " " + " " + " abc " + " " + " ")

    def test_idempotence(self):
        for s in (
            "",
            "abc",
            "a\u0000b\u200Bc\u007Fd",
            "  hi  \u0007 there \u200B ",
            "你好\u0000世界",
        ):
            once = sweep(s)
            twice = sweep(once)
            self.assertEqual(once, twice, f"idempotence failed for {s!r}")

    def test_determinism(self):
        # Same input must always produce byte-identical output.
        a = sweep("a\u200Bb\u0007c\u202Ed你好")
        b = sweep("a\u200Bb\u0007c\u202Ed你好")
        self.assertEqual(a, b)


# ---------------------------------------------------------------------------
# Reporting helpers
# ---------------------------------------------------------------------------


class SweepReportTests(unittest.TestCase):
    def test_empty_report(self):
        r = sweep_report("")
        self.assertEqual(r.original, "")
        self.assertEqual(r.swept, "")
        self.assertEqual(r.replaced_count, 0)
        self.assertEqual(r.replaced_codepoints, frozenset())
        self.assertEqual(r.length_delta, 0)

    def test_no_replacements_report(self):
        r = sweep_report("hello 你好")
        self.assertEqual(r.swept, "hello 你好")
        self.assertEqual(r.replaced_count, 0)
        self.assertEqual(r.replaced_codepoints, frozenset())
        self.assertEqual(r.length_delta, 0)

    def test_single_replacement(self):
        r = sweep_report("a\u0000b")
        self.assertEqual(r.swept, "a b")
        self.assertEqual(r.replaced_count, 1)
        self.assertEqual(r.replaced_codepoints, frozenset("\u0000"))
        self.assertEqual(r.length_delta, 0)

    def test_distinct_codepoints_set(self):
        # Two different sweep codepoints appear twice each. The
        # replaced_count is 4; the distinct set has two members.
        r = sweep_report("\u0000\u0000\u200B\u200B")
        self.assertEqual(r.swept, "    ")
        self.assertEqual(r.replaced_count, 4)
        self.assertEqual(r.replaced_codepoints, frozenset("\u0000\u200B"))

    def test_report_original_unchanged(self):
        original = "abc\u0000\u200B"
        r = sweep_report(original)
        self.assertEqual(r.original, original)
        self.assertEqual(r.swept, "abc  ")

    def test_report_length_delta_zero(self):
        # The sweep is a 1:1 substitution; delta must always be 0.
        for s in ("", "a", "a\u0000b\u200Bc", "你好\u0001世界\u202A"):
            r = sweep_report(s)
            self.assertEqual(r.length_delta, 0, f"delta for {s!r}")
            self.assertEqual(len(r.swept), len(s))

    def test_report_preserves_non_sweep_chars_verbatim(self):
        # The CJK and emoji in the report's swept field must be the
        # same objects/codepoints as in the original.
        r = sweep_report("a\u0000b你好👋c\u200Bd")
        self.assertEqual(r.swept, "a b你好👋c d")

    def test_expected_replacements_empty(self):
        count, distinct = expected_replacements("")
        self.assertEqual(count, 0)
        self.assertEqual(distinct, frozenset())

    def test_expected_replacements_matches_sweep_report(self):
        for s in (
            "abc",
            "a\u0000b",
            "\u200B\u200B\u007F",
            "你好\u0000世界\u202A\u202A",
            "x",
        ):
            count, distinct = expected_replacements(s)
            r = sweep_report(s)
            self.assertEqual(count, r.replaced_count, f"count for {s!r}")
            self.assertEqual(distinct, r.replaced_codepoints,
                             f"distinct for {s!r}")


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------


class InputValidationTests(unittest.TestCase):
    def test_non_string_input_raises(self):
        for bad in (None, 0, 1.5, b"abc", ["a"], {"a": 1}, ("a",), object()):
            with self.assertRaises(SweepError, msg=f"input={bad!r}"):
                sweep(bad)
            with self.assertRaises(SweepError, msg=f"input={bad!r}"):
                sweep_report(bad)
            with self.assertRaises(SweepError, msg=f"input={bad!r}"):
                expected_replacements(bad)


# ---------------------------------------------------------------------------
# Parity with the verifier and the supplied client
# ---------------------------------------------------------------------------


class ParityTests(unittest.TestCase):
    """The verifier and the supplied client must agree with the sweep."""

    def test_matches_verifier_sweep(self):
        # ``technocore_verify.sweep`` re-exports from this module
        # since v0.7.0. This test guarantees that import path stays
        # in lockstep so a future refactor cannot silently diverge.
        for s in (
            "",
            "abc",
            "a\u0000b\u200Bc\u007Fd\u202Ae",
            "你好,世界\u0001👋",
            "  leading and trailing  \u0007 ",
        ):
            self.assertEqual(sweep(s), verifier_sweep(s), f"diverged on {s!r}")

    def test_matches_client_sweep(self):
        # Mirror the supplied Hermes client's ``sweep`` rule with a
        # local copy here. The rule is: replace any codepoint where
        # ``o < 32`` or ``0x7F <= o <= 0x9F`` or
        # ``0x200B <= o <= 0x200F`` or ``0x202A <= o <= 0x202E``.
        def client_sweep(text: str) -> str:
            out = []
            for ch in text:
                o = ord(ch)
                if (
                    o < 32
                    or 0x7F <= o <= 0x9F
                    or 0x200B <= o <= 0x200F
                    or 0x202A <= o <= 0x202E
                ):
                    out.append(" ")
                else:
                    out.append(ch)
            return "".join(out)

        for s in (
            "",
            "hello",
            "a\u0000b",
            "x\u200By\u007Ez",
            "\u202A\u202B\u202C\u202D\u202E",
            "日本語テスト",
            "👋 world",
            "abc\u00A0def",
        ):
            self.assertEqual(sweep(s), client_sweep(s), f"diverged on {s!r}")


# ---------------------------------------------------------------------------
# Protocol contract: sweep + canonical join reproduces the verifier
# ---------------------------------------------------------------------------


class CanonicalContractTests(unittest.TestCase):
    """``sweep`` + the canonical join must equal ``technocore_verify.canonical_bytes``."""

    def test_sweep_then_join_matches_verifier(self):
        from src.technocore_verify import canonical_bytes

        cases = [
            ("lobby", "1787904075807", "hello"),
            ("lobby", "1787904075807", ""),
            ("lobby", "1", "a\u0000b\u200Bc"),
            ("dev", "9999999999999999999", "你好,世界\u0001👋"),
            ("agents", "42", "  trimmed-by-anyone  "),
        ]
        for room, nonce, text in cases:
            expected = canonical_bytes(room, nonce, text)
            actual = f"{room}|{nonce}|{sweep(text)}".encode("utf-8")
            self.assertEqual(
                actual,
                expected,
                f"diverged for room={room!r} nonce={nonce!r} text={text!r}",
            )


if __name__ == "__main__":
    unittest.main()
