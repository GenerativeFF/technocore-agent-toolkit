"""Unit tests for :mod:`src.technocore_dupe_form`.

The duplicate-filter canonical form is a pure function over a
Python ``str`` that applies, in order, NFKC normalization, full
case folding, and whitespace folding. The test suite enumerates
the contract for each fold independently, exercises the
documented examples from the official reference (``Việt`` NFC
vs NFD, ``Straße``, ``+1``), and locks down the
no-amplification, idempotence, determinism, and type-rejection
contracts.
"""
from __future__ import annotations

import os
import sys
import unicodedata
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
from src.technocore_dupe_form import (  # noqa: E402
    DUPE_FORM_VERSION,
    DupeFormError,
    DupeFormResult,
    dupe_form,
    validate_dupe_form,
)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------


class ConstantsTests(unittest.TestCase):
    """The exported constants must agree with the documented invariant."""

    def test_version_is_a_positive_int(self) -> None:
        self.assertIsInstance(DUPE_FORM_VERSION, int)
        self.assertGreaterEqual(DUPE_FORM_VERSION, 1)


# ---------------------------------------------------------------------------
# NFKC fold
# ---------------------------------------------------------------------------


class NfkcFoldTests(unittest.TestCase):
    """NFKC must collapse NFC / NFD of the same text to one form."""

    def test_nfc_viet_four_codepoints(self) -> None:
        # The "Việt" example from the official NORMALIZATION
        # section: precomposed (NFC) is 4 codepoints.
        self.assertEqual(len("Việt"), 4)

    def test_nfd_viet_six_codepoints(self) -> None:
        # Decomposed (NFD) of the same string is 6 codepoints.
        self.assertEqual(len(unicodedata.normalize("NFD", "Việt")), 6)

    def test_nfc_and_nfd_compare_different_as_strings(self) -> None:
        # The reference is explicit: NFC and NFD of one word
        # are two different messages on the server. The raw
        # strings MUST compare different.
        self.assertNotEqual("Việt", unicodedata.normalize("NFD", "Việt"))

    def test_dupe_form_collapses_nfc_and_nfd(self) -> None:
        # But the duplicate-filter comparison form MUST be
        # identical for the two byte sequences, otherwise a
        # client cannot predict the 5-copy counter from
        # outside the server.
        nfc = dupe_form("Việt")
        nfd = dupe_form(unicodedata.normalize("NFD", "Việt"))
        self.assertEqual(nfc, nfd)
        # And the canonical form must itself be the 4-codepoint
        # precomposed string, since NFKC + casefold cannot
        # leave any of the original decomposition marks in
        # place.
        self.assertEqual(nfc, "việt")
        self.assertEqual(len(nfc), 4)

    def test_nfkc_collapses_fullwidth_letters(self) -> None:
        # Fullwidth Latin letters are NFKC-equivalent to
        # their ASCII counterparts. The duplicate filter
        # must treat "ＡＢＣ" and "ABC" as the same text.
        self.assertEqual(dupe_form("ＡＢＣ"), "abc")
        self.assertEqual(dupe_form("ABC"), "abc")
        self.assertEqual(dupe_form("ＡＢＣ"), dupe_form("ABC"))

    def test_nfkc_collapses_compatibility_decomposition(self) -> None:
        # The circled-numbers block (①②③) decomposes under
        # NFKC to the bare digit. The duplicate filter must
        # treat "①②③" and "123" as the same text.
        self.assertEqual(dupe_form("①②③"), "123")
        self.assertEqual(dupe_form("123"), "123")
        self.assertEqual(dupe_form("①②③"), dupe_form("123"))

    def test_nfkc_collapses_fullwidth_and_circled(self) -> None:
        # Fullwidth digits (０１２) decompose under NFKC to
        # the bare digit; the duplicate filter must treat
        # "０１２" and "012" as the same text.
        self.assertEqual(dupe_form("０１２"), "012")
        self.assertEqual(dupe_form("０１２"), dupe_form("012"))

    def test_nfkc_preserves_emoji(self) -> None:
        # Emoji like "🚀" do not have a compatibility
        # decomposition; NFKC must leave them alone. The
        # casefold step is a no-op for emoji.
        self.assertEqual(dupe_form("🚀"), "🚀")


# ---------------------------------------------------------------------------
# Case fold
# ---------------------------------------------------------------------------


class CaseFoldTests(unittest.TestCase):
    """``str.casefold()`` is the standard reference for case fold."""

    def test_lowercase_stays_lowercase(self) -> None:
        self.assertEqual(dupe_form("hello"), "hello")

    def test_uppercase_folds_to_lowercase(self) -> None:
        self.assertEqual(dupe_form("HELLO"), "hello")

    def test_mixed_case_folds_to_lowercase(self) -> None:
        self.assertEqual(dupe_form("Hello World"), "hello world")

    def test_german_sharp_s_folds_to_ss(self) -> None:
        # ``str.casefold()`` (unlike ``str.lower()``) folds
        # the German sharp-s to "ss". The duplicate filter
        # must treat "Straße" and "STRASSE" as the same
        # text; that is the whole point of "case folded" in
        # the spec.
        self.assertEqual(dupe_form("Straße"), "strasse")
        self.assertEqual(dupe_form("STRASSE"), "strasse")
        # And the form is byte-for-byte identical.
        self.assertEqual(
            dupe_form("Straße"),
            dupe_form("STRASSE"),
        )

    def test_greek_final_sigma_folds_to_sigma(self) -> None:
        # Greek sigma has two lowercase forms: σ (U+03C3)
        # and ς (U+03C2, word-final). Both casefold to σ,
        # so the duplicate filter must treat them as the
        # same text.
        self.assertEqual(dupe_form("σ"), "σ")
        self.assertEqual(dupe_form("ς"), "σ")
        self.assertEqual(dupe_form("σ"), dupe_form("ς"))

    def test_accented_letters_preserved_after_casefold(self) -> None:
        # Most accented letters casefold to themselves
        # because lowercase accented letters are already in
        # the lowercase range.
        self.assertEqual(dupe_form("café"), "café")
        self.assertEqual(dupe_form("CAFÉ"), "café")

    def test_conversational_repeats_round_trip(self) -> None:
        # The DUPLICATES section explicitly mentions
        # "ok", "gm", and "+1" as conversational repeats
        # that are exempt at the length floor. The fold
        # must still produce a stable form for them; the
        # length-floor exemption is a server-side decision,
        # not a fold decision.
        self.assertEqual(dupe_form("ok"), "ok")
        self.assertEqual(dupe_form("OK"), "ok")
        self.assertEqual(dupe_form("Ok"), "ok")
        self.assertEqual(dupe_form("gm"), "gm")
        self.assertEqual(dupe_form("GM"), "gm")
        self.assertEqual(dupe_form("+1"), "+1")
        # And the form is identical across case.
        self.assertEqual(dupe_form("ok"), dupe_form("OK"))


# ---------------------------------------------------------------------------
# Whitespace fold
# ---------------------------------------------------------------------------


class WhitespaceFoldTests(unittest.TestCase):
    """Whitespace fold collapses any whitespace run to one space."""

    def test_ascii_space_folded(self) -> None:
        self.assertEqual(dupe_form("a  b"), "a b")
        self.assertEqual(dupe_form("  ab  "), "ab")
        self.assertEqual(dupe_form("a   b   c"), "a b c")

    def test_tab_folded(self) -> None:
        # Tab is whitespace per ``str.isspace()``.
        self.assertEqual(dupe_form("a\tb"), "a b")

    def test_newline_folded(self) -> None:
        # Newline is whitespace per ``str.isspace()``.
        # The single-line sweep already replaces newlines
        # with spaces, but the fold is written defensively
        # so a caller that skipped the sweep still gets a
        # stable result.
        self.assertEqual(dupe_form("a\nb"), "a b")
        self.assertEqual(dupe_form("a\r\nb"), "a b")

    def test_unicode_whitespace_folded(self) -> None:
        # U+00A0 NO-BREAK SPACE is whitespace per
        # ``str.isspace()``.
        self.assertEqual(dupe_form("a\u00a0b"), "a b")
        # U+2003 EM SPACE is whitespace per
        # ``str.isspace()``.
        self.assertEqual(dupe_form("a\u2003b"), "a b")

    def test_mixed_whitespace_folded(self) -> None:
        self.assertEqual(
            dupe_form("  hello \t world \n  foo  "),
            "hello world foo",
        )

    def test_empty_string_folds_to_empty(self) -> None:
        self.assertEqual(dupe_form(""), "")

    def test_whitespace_only_folds_to_empty(self) -> None:
        self.assertEqual(dupe_form("   "), "")
        self.assertEqual(dupe_form("\t\n\r "), "")
        self.assertEqual(dupe_form("\u00a0\u2003"), "")


# ---------------------------------------------------------------------------
# Idempotence
# ---------------------------------------------------------------------------


class IdempotenceTests(unittest.TestCase):
    """``dupe_form(dupe_form(x)) == dupe_form(x)`` for every legal ``x``."""

    def test_idempotent_on_ascii(self) -> None:
        for s in ("", "a", "hello", "Hello World", "  spaced  "):
            once = dupe_form(s)
            twice = dupe_form(once)
            self.assertEqual(once, twice, msg=f"idempotence failed for {s!r}")

    def test_idempotent_on_unicode(self) -> None:
        for s in (
            "Việt",
            unicodedata.normalize("NFD", "Việt"),
            "café",
            "CAFÉ",
            "Straße",
            "①②③",
            "🚀 hello",
        ):
            once = dupe_form(s)
            twice = dupe_form(once)
            self.assertEqual(once, twice, msg=f"idempotence failed for {s!r}")


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------


class DeterminismTests(unittest.TestCase):
    """The fold is a pure function: same input, same output, every time."""

    def test_deterministic_across_many_calls(self) -> None:
        # A 100-call loop must produce identical results
        # each time; the fold has no hidden state.
        reference = dupe_form("Hello World")
        for _ in range(100):
            self.assertEqual(dupe_form("Hello World"), reference)

    def test_deterministic_with_unicode(self) -> None:
        reference = dupe_form("Việt")
        for _ in range(100):
            self.assertEqual(dupe_form("Việt"), reference)


# ---------------------------------------------------------------------------
# Type rejection
# ---------------------------------------------------------------------------


class TypeRejectionTests(unittest.TestCase):
    """Non-string input must raise ``TypeError`` from ``dupe_form``."""

    def test_none_raises(self) -> None:
        with self.assertRaises(TypeError):
            dupe_form(None)  # type: ignore[arg-type]

    def test_bytes_raises(self) -> None:
        with self.assertRaises(TypeError):
            dupe_form(b"hello")  # type: ignore[arg-type]

    def test_int_raises(self) -> None:
        with self.assertRaises(TypeError):
            dupe_form(42)  # type: ignore[arg-type]

    def test_float_raises(self) -> None:
        with self.assertRaises(TypeError):
            dupe_form(3.14)  # type: ignore[arg-type]

    def test_bool_raises(self) -> None:
        # ``bool`` is a subclass of ``int`` in Python, so
        # this is a regression guard: a ``True`` or ``False``
        # argument must NOT silently fold to the empty
        # string.
        with self.assertRaises(TypeError):
            dupe_form(True)  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            dupe_form(False)  # type: ignore[arg-type]

    def test_list_raises(self) -> None:
        with self.assertRaises(TypeError):
            dupe_form(["hello"])  # type: ignore[arg-type]

    def test_dict_raises(self) -> None:
        with self.assertRaises(TypeError):
            dupe_form({"text": "hello"})  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# validate_dupe_form
# ---------------------------------------------------------------------------


class ValidateDupeFormTests(unittest.TestCase):
    """``validate_dupe_form`` is the structured-verdict surface."""

    def test_string_input_returns_valid_and_folded(self) -> None:
        result = validate_dupe_form("Hello World")
        self.assertIsInstance(result, DupeFormResult)
        self.assertTrue(result.valid)
        self.assertEqual(result.folded, "hello world")
        self.assertIsNone(result.reason)

    def test_empty_string_returns_valid_and_empty(self) -> None:
        result = validate_dupe_form("")
        self.assertTrue(result.valid)
        self.assertEqual(result.folded, "")

    def test_whitespace_only_returns_valid_and_empty(self) -> None:
        result = validate_dupe_form("   \t\n  ")
        self.assertTrue(result.valid)
        self.assertEqual(result.folded, "")

    def test_none_returns_invalid(self) -> None:
        result = validate_dupe_form(None)
        self.assertFalse(result.valid)
        self.assertIsNone(result.folded)
        self.assertIsNotNone(result.reason)

    def test_bytes_returns_invalid(self) -> None:
        result = validate_dupe_form(b"hello")
        self.assertFalse(result.valid)
        self.assertIsNone(result.folded)
        self.assertIsNotNone(result.reason)

    def test_int_returns_invalid(self) -> None:
        result = validate_dupe_form(42)
        self.assertFalse(result.valid)
        self.assertIsNone(result.folded)
        self.assertIsNotNone(result.reason)

    def test_result_is_frozen(self) -> None:
        # The dataclass is frozen; assigning to a field
        # must raise.
        result = validate_dupe_form("hello")
        with self.assertRaises(Exception):
            result.valid = False  # type: ignore[misc]

    def test_result_equality(self) -> None:
        # Two valid results on the same input compare equal.
        self.assertEqual(
            validate_dupe_form("Hello"),
            validate_dupe_form("HELLO"),
        )
        # And a valid result is not equal to an invalid one.
        self.assertNotEqual(
            validate_dupe_form("Hello"),
            validate_dupe_form(None),
        )


# ---------------------------------------------------------------------------
# No-amplification contract
# ---------------------------------------------------------------------------


class NoAmplificationTests(unittest.TestCase):
    """The fold / validator must never echo the input value.

    The input is untrusted data; echoing it onto any channel
    (a log, a result, an exception) is a one-bit signal that
    another agent can use to fingerprint the validator. The
    fold returns a *new* string (the folded form), but a
    structured verdict must report only a static, parameter-free
    reason string when it rejects.

    The non-string sentinels below are deliberately not Python
    ``str`` so they exercise the type-rejection path. A pure
    string sentinel would be a valid input and would never
    reach the error or reason channel.
    """

    def test_dupe_form_error_never_echoes_bytes_input(self) -> None:
        # Bytes input is rejected by the fold. The
        # TypeError message must not echo the bytes payload.
        sentinel = b"X" * 100
        with self.assertRaises(TypeError) as ctx:
            dupe_form(sentinel)  # type: ignore[arg-type]
        self.assertNotIn(sentinel.decode("ascii"), str(ctx.exception))

    def test_dupe_form_error_never_echoes_int_input(self) -> None:
        sentinel = 0xDEADBEEF
        with self.assertRaises(TypeError) as ctx:
            dupe_form(sentinel)  # type: ignore[arg-type]
        self.assertNotIn("3735928559", str(ctx.exception))
        self.assertNotIn("deadbeef", str(ctx.exception))
        self.assertNotIn("DEADBEEF", str(ctx.exception))

    def test_validate_reason_never_echoes_bytes_input(self) -> None:
        # The structured verdict's ``reason`` is a static
        # string; the bytes payload must not appear.
        sentinel = b"X" * 100
        result = validate_dupe_form(sentinel)
        self.assertFalse(result.valid)
        self.assertNotIn(sentinel.decode("ascii"), result.reason or "")

    def test_validate_reason_never_echoes_unicode_input(self) -> None:
        # A non-string sentinel containing emoji. The
        # reason must not echo the payload or the emoji.
        sentinel = ["🚀" * 50]
        result = validate_dupe_form(sentinel)
        self.assertFalse(result.valid)
        self.assertNotIn("🚀", result.reason or "")

    def test_validate_reason_never_echoes_dict_payload(self) -> None:
        # A dict payload (e.g. {"text": "secret"}) must
        # not have its values echoed in the reason.
        payload = {"text": "SENTINEL_SECRET_VALUE_DO_NOT_ECHO"}
        result = validate_dupe_form(payload)
        self.assertFalse(result.valid)
        self.assertNotIn(
            "SENTINEL_SECRET_VALUE_DO_NOT_ECHO", result.reason or ""
        )


# ---------------------------------------------------------------------------
# DupeFormError class
# ---------------------------------------------------------------------------


class DupeFormErrorTests(unittest.TestCase):
    """``DupeFormError`` is a ``ValueError`` subclass with a static message."""

    def test_is_value_error(self) -> None:
        self.assertTrue(issubclass(DupeFormError, ValueError))

    def test_can_be_raised_with_static_message(self) -> None:
        with self.assertRaises(DupeFormError) as ctx:
            raise DupeFormError("static message only")
        self.assertEqual(str(ctx.exception), "static message only")


# ---------------------------------------------------------------------------
# Signed vs comparison form
# ---------------------------------------------------------------------------


class SignedVsComparisonFormTests(unittest.TestCase):
    """The comparison form is NOT the signed payload form.

    The same text sent as NFC and NFD produces a single
    ``dupe_form`` output but two different signed payloads
    and two different stored messages. The verifier
    (``technocore_verify``) signs and verifies the raw
    post-sweep bytes; it would reject a payload that was
    folded first.
    """

    def test_nfc_and_nfd_have_different_signed_bytes(self) -> None:
        # NFC and NFD of the same text have different
        # UTF-8 byte lengths. The signed payload covers
        # exactly those bytes, so the two strings would
        # produce two different signatures.
        nfc_bytes = "Việt".encode("utf-8")
        nfd_bytes = unicodedata.normalize("NFD", "Việt").encode("utf-8")
        self.assertNotEqual(nfc_bytes, nfd_bytes)
        # NFC of "Việt" is 4 codepoints: V(1) + i(1) +
        # ệ(U+1EC7, 3 bytes in UTF-8) + t(1) = 6 bytes.
        self.assertEqual(len(nfc_bytes), 6)
        # NFD of "Việt" is 6 codepoints: V(1) + i(1) +
        # e(1) + combiningDotBelow(2) + combiningCircumflex(2)
        # + t(1) = 8 bytes.
        self.assertEqual(len(nfd_bytes), 8)

    def test_dupe_form_is_not_a_signed_payload_replacement(self) -> None:
        # The fold output is NOT something a caller can
        # sign in place of the original; the fold is for
        # duplicate-counting, not for signing. The simplest
        # way to lock this in: the fold output for
        # "Việt" (NFC, 4 chars) is "việt" (4 chars); the
        # raw input that produced it was a 4-codepoint
        # string. The fold is idempotent on the result, so
        # a second pass yields the same 4-codepoint
        # string. A signature over "Việt" and a
        # signature over "việt" would be different, and
        # the verifier would only accept the former.
        folded = dupe_form("Việt")
        self.assertEqual(folded, "việt")
        self.assertNotEqual("Việt", folded)
        # And the raw input is preserved by the fold only
        # in the sense that the *bytes* are transformed;
        # the fold does not keep a side channel of the
        # original.
        self.assertNotIn("V", folded)  # V was upper-case; casefold


# ---------------------------------------------------------------------------
# Sanity: a real-world example
# ---------------------------------------------------------------------------


class RealWorldExampleTests(unittest.TestCase):
    """Documented examples from the official reference."""

    def test_viet_precomposed_vs_decomposed_collapse(self) -> None:
        # Quoted from NORMALIZATION: "Việt is 4 characters
        # and 12 URL bytes precomposed, 6 and 16
        # decomposed." The 4 codepoints vs 6 codepoints
        # claim is the part we verify here; the URL-byte
        # counts are routing-layer details that belong in
        # the chunker and the protocol notes, not in the
        # duplicate-filter form.
        nfc = "Việt"
        nfd = unicodedata.normalize("NFD", nfc)
        self.assertEqual(len(nfc), 4)
        self.assertEqual(len(nfc.encode("utf-8")), 6)
        self.assertEqual(len(nfd), 6)
        self.assertEqual(len(nfd.encode("utf-8")), 8)
        # And the fold is identical for both forms.
        self.assertEqual(dupe_form(nfc), dupe_form(nfd))

    def test_viet_fold_is_viet(self) -> None:
        # The precomposed form folds to the precomposed
        # form, case-folded.
        self.assertEqual(dupe_form("Việt"), "việt")

    def test_long_sentence_fold(self) -> None:
        # A long sentence with mixed case, NFC / NFD
        # interop, and whitespace.
        sentence = "  Café ở Việt Nam  rất ngon!  "
        folded = dupe_form(sentence)
        self.assertEqual(folded, "café ở việt nam rất ngon!")
        # And the NFD form folds to the same string.
        nfd = unicodedata.normalize("NFD", sentence)
        self.assertEqual(dupe_form(nfd), folded)


if __name__ == "__main__":
    unittest.main()
