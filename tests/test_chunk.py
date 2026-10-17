"""Unit tests for ``technocore_chunk``.

The chunker is a pure function that splits a string into pieces
each no longer than ``max_len`` (default 4096, the documented
Technocore per-message size cap). Tests cover:

* identity: empty input, single short input, single exact-fit input;
* contract: every chunk has ``len(chunk) <= max_len``;
* round-trip: ``"".join(chunk_message(text)) == text`` for every
  legal input (the property callers actually care about);
* whitespace-boundary preference: a split lands on a whitespace
  boundary when one is available in the window;
* hard-cut fallback: when no whitespace boundary is available
  inside the window, the chunker cuts exactly at ``max_len``;
* oversize single token: a single whitespace-free token longer
  than ``max_len`` is emitted as a single chunk so the caller can
  decide what to do;
* Unicode preservation: CJK, emoji, combining marks, NBSP, and
  bidi codepoints are preserved byte-for-byte;
* sweep interaction: a string of replaced sweep codepoints chunks
  just like any other string; the chunker does not run the sweep
  itself;
* input validation: non-``str`` text, non-``int`` ``max_len``,
  ``bool`` ``max_len``, and non-positive ``max_len`` all raise
  :class:`ChunkError` with a static message that never echoes the
  input value;
* version pin: :data:`CHUNK_VERSION` is an integer >= 1 so callers
  can detect a contract change.

The chunker is a pure function. There is no network I/O, no
subprocess, no decoding.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src.technocore_chunk import (  # noqa: E402
    CHUNK_VERSION,
    DEFAULT_MAX_LEN,
    ChunkError,
    chunk_message,
)


# ---------------------------------------------------------------------------
# Constants / structure
# ---------------------------------------------------------------------------


class StructureTests(unittest.TestCase):
    def test_default_max_len_matches_documented_cap(self):
        # The 4096-character per-message size cap is documented in
        # the platform. If a future release changes the cap, this
        # test must be updated in the same commit that changes
        # ``DEFAULT_MAX_LEN``.
        self.assertEqual(DEFAULT_MAX_LEN, 4096)
        self.assertIsInstance(DEFAULT_MAX_LEN, int)

    def test_chunk_version_is_a_positive_integer(self):
        # The version integer exists so callers can detect a contract
        # change. It must be a positive integer; bumping it is a
        # semver-minor event for the chunker module.
        self.assertIsInstance(CHUNK_VERSION, int)
        self.assertGreaterEqual(CHUNK_VERSION, 1)


# ---------------------------------------------------------------------------
# Identity / happy path
# ---------------------------------------------------------------------------


class IdentityTests(unittest.TestCase):
    def test_empty_string_returns_empty_list(self):
        # The chunker must not produce a phantom empty chunk for
        # empty input; round-trip on "" is "" with zero chunks.
        self.assertEqual(chunk_message(""), [])

    def test_short_ascii_passes_through(self):
        # A string strictly shorter than the cap is one chunk and
        # is the original string.
        s = "hello world"
        self.assertEqual(chunk_message(s), [s])

    def test_exact_fit_is_one_chunk(self):
        # A string whose ``len()`` exactly equals max_len is a
        # single chunk, no trailing empty chunk.
        s = "a" * DEFAULT_MAX_LEN
        chunks = chunk_message(s)
        self.assertEqual(chunks, [s])

    def test_one_over_cap_is_two_chunks(self):
        # One character past the cap with whitespace at the boundary
        # must split into exactly two chunks. This is the canonical
        # "post refused for size" scenario from the field report that
        # motivated this module. The string has whitespace so the
        # chunker can actually split; the pure oversize-token case
        # is covered by ``test_long_single_token_becomes_one_chunk``.
        s = ("a" * DEFAULT_MAX_LEN) + " " + "b"
        chunks = chunk_message(s)
        self.assertEqual(len(chunks), 2)
        for c in chunks:
            self.assertLessEqual(len(c), DEFAULT_MAX_LEN)
        # The first chunk is the 4096 'a' chars, the second is
        # the trailing space + 'b'.
        self.assertEqual(chunks[0], "a" * DEFAULT_MAX_LEN)
        self.assertEqual(chunks[1], " b")
        self.assertEqual("".join(chunks), s)


# ---------------------------------------------------------------------------
# Per-chunk length contract
# ---------------------------------------------------------------------------


class LengthContractTests(unittest.TestCase):
    def test_every_chunk_within_budget_default(self):
        # Random English-style text: a mix of short and long tokens.
        s = ("the quick brown fox jumps over the lazy dog "
             "aenean commodo ligula eget dolor aenean massa "
             "cum sociis natoque penatibus et magnis dis parturient") * 200
        for c in chunk_message(s):
            self.assertLessEqual(len(c), DEFAULT_MAX_LEN)

    def test_every_chunk_within_custom_budget(self):
        # A short string whose tokens all fit inside the budget.
        # We use "a b c d e f g h i j k l m n o p" so every token
        # is 1 char and every whitespace is 1 char, guaranteeing no
        # oversize tokens are produced.
        s = " ".join("abcdefghijklmnop")
        for budget in (1, 2, 7, 100, 1000):
            for c in chunk_message(s, max_len=budget):
                self.assertLessEqual(len(c), budget,
                                     f"chunk over budget {budget}: {c!r}")

    def test_custom_budget_one_produces_one_char_chunks(self):
        # Edge case: with a budget of 1 and a string whose tokens are
        # all 1 char, every chunk is exactly 1 char. ``"a b c d e f"``
        # has 1-char tokens separated by 1-char spaces, so it splits
        # cleanly.
        s = "a b c d e f"
        self.assertEqual(chunk_message(s, max_len=1), list(s))

    def test_no_chunk_is_empty(self):
        # No chunk should ever be the empty string; the splitter
        # is contractually required to advance ``i`` by at least
        # one codepoint per iteration.
        s = "a" * (DEFAULT_MAX_LEN * 5)
        for c in chunk_message(s):
            self.assertNotEqual(c, "")


# ---------------------------------------------------------------------------
# Round-trip
# ---------------------------------------------------------------------------


class RoundTripTests(unittest.TestCase):
    def test_round_trip_ascii(self):
        s = "the quick brown fox jumps over the lazy dog " * 200
        self.assertEqual("".join(chunk_message(s)), s)

    def test_round_trip_exact_boundary(self):
        # 4096-char run, no whitespace boundary available.
        s = "a" * DEFAULT_MAX_LEN
        self.assertEqual("".join(chunk_message(s)), s)

    def test_round_trip_one_past_boundary(self):
        s = "a" * (DEFAULT_MAX_LEN + 1)
        self.assertEqual("".join(chunk_message(s)), s)

    def test_round_trip_mixed(self):
        s = "word " * 5000  # 25000 chars, lots of whitespace
        self.assertEqual("".join(chunk_message(s)), s)

    def test_round_trip_unicode_cjk(self):
        # CJK codepoints must be preserved exactly across the split.
        # The full-width comma (U+FF0C) and full stop (U+3002) are
        # not whitespace per ``str.isspace()``, so the string is a
        # single token if it has no spaces; we add spaces so the
        # chunker can actually split it.
        s = "你好,世界。 " * 1000  # trailing space per repetition
        self.assertEqual("".join(chunk_message(s)), s)
        for c in chunk_message(s):
            self.assertLessEqual(len(c), DEFAULT_MAX_LEN)

    def test_round_trip_unicode_emoji(self):
        # Emoji live in the supplementary planes; the chunker must
        # not split between surrogate halves because it counts
        # codepoints (``len()``), not UTF-16 code units.
        s = "👋🌍🚀 " * 2000
        self.assertEqual("".join(chunk_message(s)), s)
        for c in chunk_message(s):
            # Each chunk can be at most DEFAULT_MAX_LEN codepoints.
            self.assertLessEqual(len(c), DEFAULT_MAX_LEN)
            # And it must not end on a lone high surrogate, which
            # would indicate a code-unit-based cut.
            for ch in c:
                cp = ord(ch)
                self.assertFalse(0xD800 <= cp <= 0xDFFF,
                                 f"lone surrogate in chunk: {c!r}")

    def test_round_trip_combining_marks(self):
        # Combining marks are independent codepoints; the chunker
        # treats them as their own positions, which is the only
        # sound behavior at the codepoint level.
        s = ("e\u0301" + "a\u0308" + "o\u0302") * 2000
        self.assertEqual("".join(chunk_message(s)), s)

    def test_round_trip_nbsp(self):
        # U+00A0 (NBSP) is whitespace per str.isspace(); it can
        # legitimately appear as a split point.
        s = ("mot\u00A0" + "le\u00A0") * 2000
        self.assertEqual("".join(chunk_message(s)), s)

    def test_round_trip_sweep_codepoints(self):
        # The chunker does not run the sweep, but a string of
        # sweep-target codepoints (C0 controls, ZWSP, bidi) must
        # still chunk deterministically and round-trip cleanly.
        s = "\u0000\u0001\u200B\u202A" * 2000
        self.assertEqual("".join(chunk_message(s)), s)


# ---------------------------------------------------------------------------
# Split-point preference
# ---------------------------------------------------------------------------


class SplitPointTests(unittest.TestCase):
    def test_prefers_whitespace_boundary_over_hard_cut(self):
        # 30 'a' chars, one space, 19 'b' chars. With a 35-char
        # budget, the splitter must use the whitespace at position 30
        # (which is inside the window) as the cut point instead of
        # hard-cutting at position 35.
        head = "a" * 30
        tail = "b" * 19  # 30 + 1 + 19 = 50
        s = head + " " + tail
        chunks = chunk_message(s, max_len=35)
        self.assertEqual(len(chunks), 2)
        # The split advances past the whitespace, so the leading
        # chunk keeps the trailing space with it and the trailing
        # chunk starts with the next token (``b``), not a stranded
        # space.
        self.assertEqual(chunks[0], head + " ")
        self.assertEqual(chunks[1], tail)
        self.assertTrue(chunks[0].endswith(" "))
        self.assertTrue(chunks[1].startswith("b"))

    def test_prefers_latest_whitespace_boundary(self):
        # With multiple whitespace candidates in the window, the
        # splitter must use the *latest* one so the chunks are as
        # full as possible. The string has a single space every
        # other char for the first 20 chars, then 30 'b' chars.
        s = "a a a a a a a a a a " + "b" * 30
        chunks = chunk_message(s, max_len=20)
        # Latest whitespace in the window is at position 19; the
        # cut is right after it, so the first chunk is exactly
        # 20 chars (the first 20 chars of ``s``).
        self.assertEqual(len(chunks[0]), 20)
        self.assertEqual(chunks[0], s[:20])
        # The remaining 30 'b' chars are a single oversize token
        # (no whitespace), so they become the second chunk.
        self.assertEqual(chunks[1], "b" * 30)
        self.assertTrue(chunks[1].startswith("b"))

    def test_hard_cut_when_no_whitespace_in_window(self):
        # A 30-char run of 'a' followed by a space and a 'b': the
        # window [0, 30) has no whitespace, so the chunker cannot
        # find a split point inside it. Because the rest of the
        # text is a single 'b' (which is shorter than the budget),
        # the chunker hard-cuts at 30 and the second chunk is the
        # remainder. This exercises the hard-cut path with a
        # non-oversize trailing token.
        s = "a" * 30 + " " + "b"
        chunks = chunk_message(s, max_len=30)
        self.assertEqual(chunks, ["a" * 30, " b"])
        self.assertEqual("".join(chunks), s)

    def test_long_single_token_becomes_one_chunk(self):
        # A single 8000-char token (no whitespace) under the default
        # cap of 4096 must be emitted as a single chunk. The chunker
        # does not silently truncate; the caller's policy decides
        # whether the post is acceptable.
        s = "x" * 8000
        chunks = chunk_message(s)
        self.assertEqual(chunks, [s])
        self.assertGreater(len(chunks[0]), DEFAULT_MAX_LEN)

    def test_long_token_under_custom_budget(self):
        # A 100-char token under a 50-char budget: one chunk of 100
        # chars (the oversize token) plus nothing else.
        s = "x" * 100
        chunks = chunk_message(s, max_len=50)
        self.assertEqual(chunks, [s])

    def test_split_advances_past_consecutive_whitespace(self):
        # A run of multiple spaces must not produce a stranded
        # whitespace-only chunk or be split in the middle of a
        # whitespace run. The splitter anchors on a "whitespace
        # followed by non-whitespace" pair, so 20 'a' chars + 4
        # spaces + 20 'b' chars at max_len=30 splits at position
        # 24 (right after the 4 spaces), giving a 24-char leading
        # chunk and a 16-char trailing chunk.
        s = "a" * 20 + "    " + "b" * 20
        chunks = chunk_message(s, max_len=30)
        self.assertEqual(len(chunks), 2)
        # The leading chunk owns the 4 spaces; it is not whitespace-
        # only and it is not stranded mid-run.
        self.assertEqual(chunks[0], "a" * 20 + "    ")
        # The trailing chunk starts with the next token, not with
        # whitespace, and is non-empty.
        self.assertEqual(chunks[1], "b" * 20)
        self.assertTrue(chunks[1].startswith("b"))
        self.assertGreater(len(chunks[1].lstrip()), 0)


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------


class DeterminismTests(unittest.TestCase):
    def test_repeated_calls_are_identical(self):
        s = ("alpha beta gamma delta epsilon zeta eta theta "
             "iota kappa lambda mu") * 500
        a = chunk_message(s)
        b = chunk_message(s)
        self.assertEqual(a, b)

    def test_oversize_token_determinism(self):
        s = "x" * 12345 + "y"
        a = chunk_message(s)
        b = chunk_message(s)
        self.assertEqual(a, b)
        self.assertEqual("".join(a), s)


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------


class InputValidationTests(unittest.TestCase):
    def test_non_str_text_raises(self):
        for bad in (b"hello", 42, 3.14, None, ["a"], {"x": 1}, ("a",)):
            with self.assertRaises(ChunkError):
                chunk_message(bad)  # type: ignore[arg-type]

    def test_non_int_max_len_raises(self):
        for bad in ("100", 1.5, None, [10], {"x": 10}):
            with self.assertRaises(ChunkError):
                chunk_message("hello", max_len=bad)  # type: ignore[arg-type]

    def test_bool_max_len_is_rejected(self):
        # ``True`` and ``False`` are ints in Python, but a silent
        # conversion to ``1`` or ``0`` is a footgun. Reject them
        # explicitly.
        with self.assertRaises(ChunkError):
            chunk_message("hello", max_len=True)
        with self.assertRaises(ChunkError):
            chunk_message("hello", max_len=False)

    def test_zero_max_len_raises(self):
        with self.assertRaises(ChunkError):
            chunk_message("hello", max_len=0)

    def test_negative_max_len_raises(self):
        for bad in (-1, -100, -4096):
            with self.assertRaises(ChunkError):
                chunk_message("hello", max_len=bad)

    def test_error_message_does_not_echo_input(self):
        # The exception message must be static; it must not contain
        # any portion of the offending input. The chunker is a pure
        # function over untrusted data and must not amplify the
        # input onto any channel. We pass a ``bytes`` sentinel (a
        # non-``str``) so the type check fails and a ``ChunkError``
        # is raised.
        sentinel = b"rm -rf / ; DROP TABLE secrets; --"
        try:
            chunk_message(sentinel)  # type: ignore[arg-type]
        except ChunkError as exc:
            self.assertNotIn("rm", str(exc))
            self.assertNotIn("DROP", str(exc))
            self.assertNotIn("secrets", str(exc))
            self.assertNotIn(sentinel.decode("latin-1"), str(exc))
        else:
            self.fail("expected ChunkError for non-str text")


# ---------------------------------------------------------------------------
# Interaction with the sweep (the chunker does not sweep)
# ---------------------------------------------------------------------------


class SweepInteractionTests(unittest.TestCase):
    def test_chunker_does_not_run_sweep(self):
        # A string with a U+0000 inside it should chunk as-is; the
        # chunker must not substitute the control char with a space.
        s = "a" * 10 + "\u0000" + "b" * 10
        chunks = chunk_message(s, max_len=15)
        joined = "".join(chunks)
        self.assertEqual(joined, s)
        # And the U+0000 must still be present in the joined output
        # so the round-trip property holds.
        self.assertIn("\u0000", joined)

    def test_chunker_preserves_sweep_target_codepoints(self):
        # Even at a chunk boundary, sweep-target codepoints are not
        # silently rewritten. A caller that wants post-sweep text
        # must call :func:`technocore_sweep.sweep` first.
        s = ("hello\u200B" + "world\u0007") * 1000
        joined = "".join(chunk_message(s))
        self.assertEqual(joined, s)
        self.assertIn("\u200B", joined)
        self.assertIn("\u0007", joined)


# ---------------------------------------------------------------------------
# Parity with the documented size cap
# ---------------------------------------------------------------------------


class DocumentedCapTests(unittest.TestCase):
    def test_4096_char_input_fits_default(self):
        s = "x" * 4096
        self.assertEqual(chunk_message(s), [s])

    def test_4097_char_input_is_one_oversize_chunk(self):
        # A 4097-char string with no whitespace is a single
        # oversize token under the documented contract. It must be
        # emitted as one chunk; the chunker does not silently
        # truncate.
        s = "x" * 4097
        chunks = chunk_message(s)
        self.assertEqual(chunks, [s])
        self.assertEqual(len(chunks[0]), 4097)

    def test_4096_plus_one_with_separator_is_two_chunks(self):
        # The same 4097-char payload, but with a whitespace at the
        # cap boundary so the chunker can actually split. This is
        # the canonical "post refused for size" case from the field
        # report.
        s = "x" * 4096 + " " + "y"
        chunks = chunk_message(s)
        self.assertEqual(len(chunks), 2)
        self.assertEqual(chunks[0], "x" * 4096)
        self.assertEqual(chunks[1], " y")
        self.assertEqual("".join(chunks), s)

    def test_8192_char_input_is_one_oversize_chunk(self):
        s = "x" * 8192
        chunks = chunk_message(s)
        self.assertEqual(chunks, [s])
        self.assertEqual(len(chunks[0]), 8192)

    def test_8193_char_input_is_one_oversize_chunk(self):
        s = "x" * 8193
        chunks = chunk_message(s)
        self.assertEqual(chunks, [s])
        self.assertEqual(len(chunks[0]), 8193)


if __name__ == "__main__":
    unittest.main()
