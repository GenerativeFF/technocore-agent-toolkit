"""Unit tests for :mod:`src.technocore_binding`.

The binding surface of a Technocore room record is the set of
fields the signature actually covers. The canonical signed bytes
contain ``room``, ``nonce``, and ``text`` only, so ``ts`` and
``seq`` are server assertions that a verifying client must not
mistake for signed data.

The suite locks down the three-way field model, the read-API to
verifier normalization (including the ``from`` to ``did`` rename
and the integer-nonce re-encode), parity of the canonical SHA-256
with :mod:`src.technocore_verify`, the no-amplification contract
on ``reason`` strings, determinism, and an end-to-end round trip in
which a real Ed25519 signature over a real canonical payload is
normalized from a server-shaped record and accepted by the
verifier.
"""
from __future__ import annotations

import base64
import hashlib
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
from src.technocore_binding import (  # noqa: E402
    BINDING_VERSION,
    BindingError,
    BindingReport,
    IDENTITY_FIELDS,
    SERVER_ASSERTED_FIELDS,
    SERVER_FROM_FIELD,
    SIGNED_FIELDS,
    SIGNATURE_FIELD,
    VERIFIER_DID_FIELD,
    binding_report,
    to_verifier_payload,
)
from src.technocore_verify import (  # noqa: E402
    canonical_bytes,
    did_from_public_key,
    verify,
)

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from cryptography.hazmat.primitives.serialization import (  # noqa: E402
    Encoding,
    PublicFormat,
)

DID = "did:key:z6MkhiRKcJjvdy1s4m6np8GgoLoqgVaRm5PmUVNKKiW9VpEZ"
NONCE = "1792493744548"
SIG = "XTINzh9gw53_kMnbC6F_UOwqGLyEnYAsrOaxchiGbIxTDbHPXZi5oaX2KwwTBb5nh0L-MRAOhsY3_IVRAllWBQ"


def _write_payload(**overrides):
    """A record in write-payload shape (``did``, string nonce, room)."""
    payload = {
        VERIFIER_DID_FIELD: DID,
        SIGNATURE_FIELD: SIG,
        "nonce": NONCE,
        "text": "hello",
        "room": "dev",
    }
    payload.update(overrides)
    return payload


def _server_record(**overrides):
    """A record in read-API shape (``from``, integer nonce, ts/seq)."""
    record = {
        SERVER_FROM_FIELD: DID,
        SIGNATURE_FIELD: SIG,
        "nonce": int(NONCE),
        "text": "hello",
        "ts": "2026-10-20T10:55:48.708802Z",
        "seq": 199735,
    }
    record.update(overrides)
    return record


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------


class ConstantsTests(unittest.TestCase):
    """The exported constants must match the documented wire format."""

    def test_signed_fields_are_room_nonce_text_in_order(self):
        self.assertEqual(SIGNED_FIELDS, ("room", "nonce", "text"))

    def test_server_asserted_fields_are_ts_and_seq(self):
        self.assertEqual(SERVER_ASSERTED_FIELDS, ("ts", "seq"))

    def test_signed_and_server_fields_do_not_overlap(self):
        overlap = set(SIGNED_FIELDS) & set(SERVER_ASSERTED_FIELDS)
        self.assertEqual(overlap, set())

    def test_server_asserted_fields_are_not_signed(self):
        for name in SERVER_ASSERTED_FIELDS:
            self.assertNotIn(name, SIGNED_FIELDS)

    def test_identity_fields_cover_both_spellings(self):
        self.assertEqual(IDENTITY_FIELDS, ("from", "did"))
        self.assertEqual(VERIFIER_DID_FIELD, "did")
        self.assertEqual(SERVER_FROM_FIELD, "from")

    def test_version_is_positive_int(self):
        self.assertIsInstance(BINDING_VERSION, int)
        self.assertGreaterEqual(BINDING_VERSION, 1)


# ---------------------------------------------------------------------------
# binding_report: the field model
# ---------------------------------------------------------------------------


class BindingModelTests(unittest.TestCase):
    """The report must state what the signature does and does not cover."""

    def test_write_payload_reports_ok(self):
        report = binding_report(_write_payload())
        self.assertTrue(report.ok)
        self.assertIsNone(report.reason)

    def test_write_payload_has_no_unsigned_server_fields(self):
        report = binding_report(_write_payload())
        self.assertEqual(report.unsigned_server_fields, ())

    def test_server_record_flags_ts_and_seq_as_unsigned(self):
        report = binding_report(_server_record(), room="dev")
        self.assertTrue(report.ok)
        self.assertEqual(report.unsigned_server_fields, ("ts", "seq"))

    def test_server_record_warns_that_ts_is_not_covered(self):
        report = binding_report(_server_record(), room="dev")
        joined = " ".join(report.warnings)
        self.assertIn("ts", joined)
        self.assertIn("not covered by the signature", joined)

    def test_server_record_warns_that_seq_is_not_covered(self):
        report = binding_report(_server_record(), room="dev")
        joined = " ".join(report.warnings)
        self.assertIn("seq", joined)
        self.assertIn("not covered by the signature", joined)

    def test_signed_fields_are_always_reported(self):
        report = binding_report(_server_record(), room="dev")
        self.assertEqual(report.signed_fields, SIGNED_FIELDS)

    def test_signature_field_is_not_listed_as_signed(self):
        self.assertNotIn(SIGNATURE_FIELD, SIGNED_FIELDS)

    def test_identity_field_reports_from_spelling(self):
        report = binding_report(_server_record(), room="dev")
        self.assertEqual(report.identity_field, "from")

    def test_identity_field_reports_did_spelling(self):
        report = binding_record_report = binding_report(_write_payload())
        self.assertEqual(binding_record_report.identity_field, "did")

    def test_identity_warns_about_from_vs_did_spelling(self):
        report = binding_report(_server_record(), room="dev")
        self.assertTrue(
            any("from" in w and "did" in w for w in report.warnings),
            report.warnings,
        )

    def test_record_without_ts_has_no_ts_warning(self):
        record = _server_record()
        del record["ts"]
        report = binding_report(record, room="dev")
        self.assertNotIn("ts", report.unsigned_server_fields)
        self.assertIn("seq", report.unsigned_server_fields)
        self.assertFalse(
            any("ts is server-asserted" in w for w in report.warnings)
        )

    def test_record_without_seq_reports_only_ts(self):
        record = _server_record()
        del record["seq"]
        report = binding_report(record, room="dev")
        self.assertNotIn("seq", report.unsigned_server_fields)
        self.assertIn("ts", report.unsigned_server_fields)


# ---------------------------------------------------------------------------
# binding_report: structural failures
# ---------------------------------------------------------------------------


class BindingFailureTests(unittest.TestCase):
    """Structurally unusable records fail with static reasons."""

    def test_missing_room_fails(self):
        record = _server_record()
        report = binding_report(record)
        self.assertFalse(report.ok)
        self.assertIsNotNone(report.reason)
        self.assertIn("room", report.reason)

    def test_record_room_wins_over_caller_room(self):
        report = binding_report(_write_payload(), room="other")
        self.assertEqual(report.room, "dev")

    def test_caller_room_used_when_record_omits_it(self):
        report = binding_report(_server_record(), room="dev")
        self.assertEqual(report.room, "dev")
        self.assertTrue(
            any("room supplied by caller" in w for w in report.warnings)
        )

    def test_missing_nonce_fails(self):
        record = _write_payload()
        del record["nonce"]
        report = binding_report(record)
        self.assertFalse(report.ok)
        self.assertIn("nonce", report.reason)

    def test_missing_text_fails(self):
        record = _write_payload()
        del record["text"]
        report = binding_report(record)
        self.assertFalse(report.ok)
        self.assertIn("text", report.reason)

    def test_non_string_text_fails(self):
        report = binding_report(_write_payload(text=None))
        self.assertFalse(report.ok)

    def test_non_integer_text_fails(self):
        report = binding_report(_write_payload(text=1234))
        self.assertFalse(report.ok)

    def test_float_nonce_rejected(self):
        report = binding_report(_write_payload(nonce=1.5e12))
        self.assertFalse(report.ok)
        self.assertIn("nonce", report.reason)

    def test_bool_nonce_rejected(self):
        report = binding_report(_write_payload(nonce=True))
        self.assertFalse(report.ok)

    def test_none_nonce_rejected(self):
        report = binding_report(_write_payload(nonce=None))
        self.assertFalse(report.ok)

    def test_empty_nonce_rejected(self):
        report = binding_report(_write_payload(nonce=""))
        self.assertFalse(report.ok)

    def test_non_decimal_nonce_rejected(self):
        report = binding_report(_write_payload(nonce="12a45"))
        self.assertFalse(report.ok)

    def test_non_mapping_raises_type_error(self):
        with self.assertRaises(TypeError):
            binding_report(["not", "a", "mapping"])

    def test_none_record_raises_type_error(self):
        with self.assertRaises(TypeError):
            binding_report(None)

    def test_empty_record_fails_gracefully(self):
        report = binding_report({})
        self.assertFalse(report.ok)
        self.assertIsInstance(report.reason, str)


# ---------------------------------------------------------------------------
# Nonce normalization
# ---------------------------------------------------------------------------


class NonceNormalizationTests(unittest.TestCase):
    """The read API's integer nonce must normalize to the signed form."""

    def test_integer_nonce_yields_same_string_nonce(self):
        report = binding_report(_server_record(), room="dev")
        self.assertEqual(report.nonce, NONCE)

    def test_integer_nonce_warns_about_rencoding(self):
        report = binding_report(_server_record(), room="dev")
        self.assertTrue(
            any("JSON number" in w for w in report.warnings), report.warnings
        )

    def test_string_nonce_does_not_warn(self):
        report = binding_report(_write_payload())
        self.assertFalse(any("JSON number" in w for w in report.warnings))

    def test_large_nonce_warns_about_float_precision(self):
        record = _server_record(nonce=(1 << 53) + 1)
        report = binding_report(record, room="dev")
        self.assertTrue(
            any("IEEE 754" in w for w in report.warnings), report.warnings
        )

    def test_exact_float53_nonce_does_not_warn(self):
        record = _server_record(nonce=(1 << 53) - 1)
        report = binding_report(record, room="dev")
        self.assertFalse(any("IEEE 754" in w for w in report.warnings))

    def test_integer_and_string_nonce_agree_on_canonical_bytes(self):
        from_int = binding_report(_server_record(), room="dev")
        from_str = binding_report(_write_payload())
        self.assertEqual(from_int.canonical_sha256, from_str.canonical_sha256)


# ---------------------------------------------------------------------------
# Canonical parity with the verifier
# ---------------------------------------------------------------------------


class CanonicalParityTests(unittest.TestCase):
    """The canonical form must have exactly one source of truth."""

    def test_sha_matches_verifier_canonical_bytes(self):
        report = binding_report(_write_payload())
        expected = hashlib.sha256(
            canonical_bytes("dev", NONCE, "hello")
        ).hexdigest()
        self.assertEqual(report.canonical_sha256, expected)

    def test_length_matches_verifier_canonical_bytes(self):
        report = binding_report(_write_payload())
        self.assertEqual(
            report.canonical_length, len(canonical_bytes("dev", NONCE, "hello"))
        )

    def test_sweeping_happens_before_hashing(self):
        # A text with a control character must hash the same as its
        # swept form, matching the verifier's sweep-then-join rule.
        raw = binding_report(_write_payload(text="he\x00llo"))
        swept = binding_report(_write_payload(text="he llo"))
        self.assertEqual(raw.canonical_sha256, swept.canonical_sha256)

    def test_room_participates_in_the_canonical_bytes(self):
        a = binding_report(_write_payload(room="dev"))
        b = binding_report(_write_payload(room="other"))
        self.assertNotEqual(a.canonical_sha256, b.canonical_sha256)

    def test_nonce_participates_in_the_canonical_bytes(self):
        a = binding_report(_write_payload(nonce=NONCE))
        b = binding_report(_write_payload(nonce="1792493744549"))
        self.assertNotEqual(a.canonical_sha256, b.canonical_sha256)


# ---------------------------------------------------------------------------
# No amplification
# ---------------------------------------------------------------------------


class NoAmplificationTests(unittest.TestCase):
    """Untrusted values must never be echoed back in reasons."""

    def test_reason_does_not_echo_nonce(self):
        report = binding_report(_write_payload(nonce="SECRETNONCE!!"))
        self.assertNotIn("SECRETNONCE", report.reason or "")

    def test_reason_does_not_echo_text(self):
        report = binding_report(_write_payload(text=None))
        self.assertNotIn("None", report.reason or "")

    def test_reason_does_not_echo_sig(self):
        record = _write_payload()
        record["nonce"] = "x" * 40
        report = binding_report(record)
        self.assertNotIn("xxxx", report.reason or "")

    def test_verifier_error_reason_is_static(self):
        report = binding_report(_write_payload(nonce="0" * 25))
        self.assertFalse(report.ok)
        self.assertIsNotNone(report.reason)
        self.assertNotIn("0000000000000000000000000", report.reason)


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------


class DeterminismTests(unittest.TestCase):
    """Repeated calls must produce identical results."""

    def test_repeated_calls_are_identical(self):
        record = _server_record()
        first = binding_report(record, room="dev")
        second = binding_report(record, room="dev")
        self.assertEqual(first, second)

    def test_does_not_mutate_input(self):
        record = _server_record()
        snapshot = dict(record)
        binding_report(record, room="dev")
        self.assertEqual(record, snapshot)

    def test_report_is_frozen(self):
        report = binding_report(_write_payload())
        with self.assertRaises(Exception):
            report.ok = False  # type: ignore[misc]


# ---------------------------------------------------------------------------
# to_verifier_payload
# ---------------------------------------------------------------------------


class ToVerifierPayloadTests(unittest.TestCase):
    """Server records must normalize into the five-field verify payload."""

    def test_renames_from_to_did(self):
        payload = to_verifier_payload(_server_record(), room="dev")
        self.assertIn(VERIFIER_DID_FIELD, payload)
        self.assertNotIn(SERVER_FROM_FIELD, payload)
        self.assertEqual(payload[VERIFIER_DID_FIELD], DID)

    def test_reencodes_integer_nonce(self):
        payload = to_verifier_payload(_server_record(), room="dev")
        self.assertEqual(payload["nonce"], NONCE)
        self.assertIsInstance(payload["nonce"], str)

    def test_drops_ts_and_seq(self):
        payload = to_verifier_payload(_server_record(), room="dev")
        self.assertNotIn("ts", payload)
        self.assertNotIn("seq", payload)

    def test_payload_has_exactly_five_fields(self):
        payload = to_verifier_payload(_server_record(), room="dev")
        self.assertEqual(
            sorted(payload.keys()),
            sorted(["did", "sig", "nonce", "text", "room"]),
        )

    def test_all_values_are_strings(self):
        payload = to_verifier_payload(_server_record(), room="dev")
        for key, value in payload.items():
            self.assertIsInstance(value, str, key)

    def test_does_not_mutate_input(self):
        record = _server_record()
        snapshot = dict(record)
        to_verifier_payload(record, room="dev")
        self.assertEqual(record, snapshot)

    def test_missing_sig_raises(self):
        record = _server_record()
        del record[SIGNATURE_FIELD]
        with self.assertRaises(BindingError):
            to_verifier_payload(record, room="dev")

    def test_missing_identity_raises(self):
        record = _server_record()
        del record[SERVER_FROM_FIELD]
        with self.assertRaises(BindingError):
            to_verifier_payload(record, room="dev")

    def test_unusable_record_raises(self):
        with self.assertRaises(BindingError):
            to_verifier_payload({})

    def test_non_mapping_raises_type_error(self):
        with self.assertRaises(TypeError):
            to_verifier_payload("nope")

    def test_binding_error_is_value_error(self):
        self.assertTrue(issubclass(BindingError, ValueError))


# ---------------------------------------------------------------------------
# End-to-end interop round trip
# ---------------------------------------------------------------------------


class RoundTripTests(unittest.TestCase):
    """A real signature must survive the read-record normalization."""

    @classmethod
    def setUpClass(cls):
        cls._key = Ed25519PrivateKey.generate()
        cls._pub = cls._key.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw
        )
        cls._did = did_from_public_key(cls._pub)

    def _signed_server_record(self, text="hello", room="dev", nonce=1792493744548):
        """Build a server-shaped record carrying a genuine signature."""
        canonical = canonical_bytes(room, str(nonce), text)
        sig = base64.urlsafe_b64encode(
            self._key.sign(canonical)
        ).rstrip(b"=").decode("ascii")
        return {
            SERVER_FROM_FIELD: self._did,
            SIGNATURE_FIELD: sig,
            "nonce": nonce,
            "text": text,
            "ts": "2026-10-20T10:55:48.708802Z",
            "seq": 199735,
        }

    def test_normalized_payload_verifies(self):
        record = self._signed_server_record()
        payload = to_verifier_payload(record, room="dev")
        result = verify(payload, self._pub)
        self.assertTrue(result.valid, result.reason)

    def test_binding_sha_matches_verifier_sha(self):
        record = self._signed_server_record()
        report = binding_report(record, room="dev")
        result = verify(to_verifier_payload(record, room="dev"), self._pub)
        self.assertEqual(report.canonical_sha256, result.canonical_sha256)

    def test_verifier_accepts_cjk_text(self):
        record = self._signed_server_record(text="こんにちは")
        payload = to_verifier_payload(record, room="dev")
        self.assertTrue(verify(payload, self._pub).valid)

    def test_tampered_text_still_fails_after_normalization(self):
        record = self._signed_server_record()
        record["text"] = "goodbye"
        payload = to_verifier_payload(record, room="dev")
        self.assertFalse(verify(payload, self._pub).valid)

    def test_tampered_ts_does_not_break_verification(self):
        """A forged ts is invisible to the signature — the point of
        this module. The record must still verify, which is exactly
        why ts must not be treated as authenticated."""
        record = self._signed_server_record()
        record["ts"] = "1999-01-01T00:00:00.000000Z"
        payload = to_verifier_payload(record, room="dev")
        self.assertTrue(verify(payload, self._pub).valid)

    def test_tampered_seq_does_not_break_verification(self):
        record = self._signed_server_record()
        record["seq"] = 1
        payload = to_verifier_payload(record, room="dev")
        self.assertTrue(verify(payload, self._pub).valid)


if __name__ == "__main__":
    unittest.main()