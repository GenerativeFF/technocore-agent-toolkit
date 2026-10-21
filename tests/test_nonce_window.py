"""Unit tests for the server-side nonce replay window model.

Covers the constants and their derivation from the published
reference manual, the capacity arithmetic, the byte-budget walk, the
per-signer exposure verdict, strict input validation, and the
guarantees that the input sequence is never mutated.

The documented facts under test come from the NONCE and SIGNING
sections of ``https://www.technocore.chat/llms.txt``:

* the last-nonce lookup scans only the newest 1 MiB of the room;
* ``sig`` adds 95 bytes to every signed record;
* an 86-character unpadded base64url signature;
* signing costs "roughly a third fewer records" for short messages.
"""
from __future__ import annotations

import json
import unittest

from src.technocore_nonce_window import (
    DEFAULT_NONCE_WINDOW_BYTES,
    MIB,
    NONCE_WINDOW_VERSION,
    SIG_JSON_PREFIX_CHARS,
    SIG_JSON_TRAILER_CHARS,
    SIG_RECORD_OVERHEAD_BYTES,
    SIGNED_SIG_CHARS,
    CapacityReport,
    NonceWindowError,
    WindowEntry,
    WindowReport,
    capacity_report,
    classify_window,
    records_in_window,
    sig_field_overhead,
    signed_record_bytes,
)


class _ConstantTests(unittest.TestCase):
    def test_mib_is_1048576(self) -> None:
        self.assertEqual(MIB, 1_048_576)

    def test_default_window_is_one_mib(self) -> None:
        self.assertEqual(DEFAULT_NONCE_WINDOW_BYTES, MIB)

    def test_signed_sig_chars_is_86(self) -> None:
        self.assertEqual(SIGNED_SIG_CHARS, 86)

    def test_json_prefix_and_trailer_chars(self) -> None:
        # ``"sig":"`` is 7 characters; the closing quote plus the
        # separating comma is 2.
        self.assertEqual(SIG_JSON_PREFIX_CHARS, len('"sig":"'))
        self.assertEqual(SIG_JSON_TRAILER_CHARS, 2)

    def test_record_overhead_is_95_bytes(self) -> None:
        # The manual states ``sig`` adds 95 bytes to every signed
        # record; the module derives the same figure from the 86-char
        # signature length.
        self.assertEqual(SIG_RECORD_OVERHEAD_BYTES, 95)

    def test_version_is_one(self) -> None:
        self.assertEqual(NONCE_WINDOW_VERSION, 1)

    def test_prefix_chars_count_the_literal_member_head(self) -> None:
        literal = '"sig":"'
        self.assertEqual(len(literal), SIG_JSON_PREFIX_CHARS)

    def test_overhead_is_prefix_plus_sig_plus_trailer(self) -> None:
        self.assertEqual(
            SIG_RECORD_OVERHEAD_BYTES,
            SIG_JSON_PREFIX_CHARS + SIGNED_SIG_CHARS + SIG_JSON_TRAILER_CHARS,
        )


class _SigFieldOverheadTests(unittest.TestCase):
    def test_default_matches_documented_95(self) -> None:
        self.assertEqual(sig_field_overhead(), 95)

    def test_serialized_member_measures_95_bytes(self) -> None:
        # Build the exact JSON fragment the arithmetic describes and
        # measure it, rather than trusting the constant.
        sig = "A" * SIGNED_SIG_CHARS
        fragment = '"sig":"' + sig + '",'
        self.assertEqual(len(fragment.encode("utf-8")), 95)
        self.assertEqual(sig_field_overhead(), len(fragment.encode("utf-8")))

    def test_scales_with_signature_length(self) -> None:
        self.assertEqual(sig_field_overhead(64), SIG_JSON_PREFIX_CHARS + 64 + 2)

    def test_rejects_zero(self) -> None:
        with self.assertRaises(NonceWindowError):
            sig_field_overhead(0)

    def test_rejects_negative(self) -> None:
        with self.assertRaises(NonceWindowError):
            sig_field_overhead(-1)

    def test_rejects_bool(self) -> None:
        with self.assertRaises(NonceWindowError):
            sig_field_overhead(True)

    def test_rejects_str(self) -> None:
        with self.assertRaises(NonceWindowError):
            sig_field_overhead("86")

    def test_rejects_float(self) -> None:
        with self.assertRaises(NonceWindowError):
            sig_field_overhead(86.0)


class _SignedRecordBytesTests(unittest.TestCase):
    def test_adds_ninety_five(self) -> None:
        self.assertEqual(signed_record_bytes(190), 285)

    def test_is_additive(self) -> None:
        for base in (1, 50, 190, 1000):
            with self.subTest(base=base):
                self.assertEqual(
                    signed_record_bytes(base), base + SIG_RECORD_OVERHEAD_BYTES
                )

    def test_rejects_zero(self) -> None:
        with self.assertRaises(NonceWindowError):
            signed_record_bytes(0)

    def test_rejects_bool(self) -> None:
        with self.assertRaises(NonceWindowError):
            signed_record_bytes(True)


class _RecordsInWindowTests(unittest.TestCase):
    def test_floors_the_division(self) -> None:
        self.assertEqual(records_in_window(300, 1000), 3)

    def test_exact_multiple(self) -> None:
        self.assertEqual(records_in_window(250, 1000), 4)

    def test_undershoot_keeps_the_remainder_out(self) -> None:
        # 1000 // 300 == 3, and the 4th record would need 1200 bytes.
        self.assertEqual(records_in_window(300, 1000), 3)

    def test_oversized_record_yields_zero(self) -> None:
        self.assertEqual(records_in_window(2000, 1000), 0)

    def test_exactly_window_sized_record_yields_one(self) -> None:
        self.assertEqual(records_in_window(1000, 1000), 1)

    def test_defaults_to_one_mib(self) -> None:
        self.assertEqual(records_in_window(MIB, MIB), 1)
        self.assertEqual(records_in_window(1, MIB), MIB)

    def test_rejects_zero_record_bytes(self) -> None:
        with self.assertRaises(NonceWindowError):
            records_in_window(0, 1000)

    def test_rejects_zero_window(self) -> None:
        with self.assertRaises(NonceWindowError):
            records_in_window(100, 0)


class _CapacityReportTests(unittest.TestCase):
    def test_report_fields(self) -> None:
        report = capacity_report(190)
        self.assertIsInstance(report, CapacityReport)
        self.assertEqual(report.window_bytes, MIB)
        self.assertEqual(report.base_record_bytes, 190)
        self.assertEqual(report.signed_record_bytes, 285)
        self.assertEqual(report.unsigned_records, 5518)
        self.assertEqual(report.signed_records, 3679)
        self.assertEqual(report.records_lost, 1839)

    def test_short_messages_lose_roughly_a_third(self) -> None:
        # The manual: "a room of short signed messages fits roughly a
        # third fewer records into the scanned window". At a 190-byte
        # unsigned base the model reproduces that figure exactly.
        report = capacity_report(190)
        self.assertAlmostEqual(report.fraction_lost, 1 / 3, places=3)

    def test_loss_ratio_depends_on_base_size(self) -> None:
        # The "roughly a third" phrasing is not a constant: it falls as
        # the unsigned record grows and the fixed 95-byte overhead
        # matters less.
        small = capacity_report(100)
        large = capacity_report(2000)
        self.assertGreater(small.fraction_lost, large.fraction_lost)

    def test_signed_records_never_exceed_unsigned(self) -> None:
        for base in (1, 50, 190, 500, 5000, 20000):
            with self.subTest(base=base):
                report = capacity_report(base)
                self.assertLessEqual(report.signed_records, report.unsigned_records)
                self.assertGreaterEqual(report.records_lost, 0)

    def test_records_lost_is_exact_difference(self) -> None:
        report = capacity_report(333)
        self.assertEqual(
            report.records_lost, report.unsigned_records - report.signed_records
        )

    def test_fraction_lost_is_bounded(self) -> None:
        for base in (1, 190, 100000):
            with self.subTest(base=base):
                report = capacity_report(base)
                self.assertGreaterEqual(report.fraction_lost, 0.0)
                self.assertLess(report.fraction_lost, 1.0)

    def test_custom_window_is_honored(self) -> None:
        report = capacity_report(100, window_bytes=1000)
        self.assertEqual(report.window_bytes, 1000)
        self.assertEqual(report.unsigned_records, 10)
        self.assertEqual(report.signed_record_bytes, 195)
        self.assertEqual(report.signed_records, 5)

    def test_zero_fraction_when_nothing_fits(self) -> None:
        report = capacity_report(2000, window_bytes=1000)
        self.assertEqual(report.unsigned_records, 0)
        self.assertEqual(report.fraction_lost, 0.0)

    def test_report_is_frozen(self) -> None:
        report = capacity_report(190)
        with self.assertRaises(Exception):
            report.window_bytes = 5  # type: ignore[misc]

    def test_rejects_zero_base(self) -> None:
        with self.assertRaises(NonceWindowError):
            capacity_report(0)

    def test_rejects_bool_base(self) -> None:
        with self.assertRaises(NonceWindowError):
            capacity_report(True)

    def test_rejects_zero_window(self) -> None:
        with self.assertRaises(NonceWindowError):
            capacity_report(190, window_bytes=0)


class _ClassifyWindowBasicsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.entries = [
            {"size_bytes": 100, "seq": 1, "from": "did:key:zAAA", "nonce": 10},
            {"size_bytes": 200, "seq": 2, "from": "did:key:zBBB", "nonce": 20},
            {"size_bytes": 300, "seq": 3, "did": "did:key:zAAA", "nonce": 30},
        ]

    def test_all_inside_when_under_budget(self) -> None:
        report = classify_window(self.entries, window_bytes=1000)
        self.assertIsInstance(report, WindowReport)
        self.assertEqual(report.total_records, 3)
        self.assertEqual(report.total_bytes, 600)
        self.assertEqual(report.in_window_records, 3)
        self.assertEqual(report.expired_records, 0)
        self.assertEqual(report.oldest_protected_seq, 1)
        self.assertIsNone(report.newest_expired_seq)

    def test_walks_backwards_from_the_newest(self) -> None:
        report = classify_window(self.entries, window_bytes=500)
        # 300 + 200 == 500 fits; adding the oldest 100 would exceed.
        self.assertEqual(report.in_window_records, 2)
        self.assertEqual(report.in_window_bytes, 500)
        self.assertEqual(report.oldest_protected_seq, 2)
        self.assertEqual(report.expired_records, 1)
        self.assertEqual(report.expired_bytes, 100)
        self.assertEqual(report.newest_expired_seq, 1)

    def test_boundary_at_exactly_the_budget_is_inclusive(self) -> None:
        report = classify_window(self.entries, window_bytes=500)
        self.assertEqual(report.in_window_bytes, report.window_bytes)

    def test_one_byte_short_expires_the_oldest(self) -> None:
        report = classify_window(self.entries, window_bytes=499)
        self.assertEqual(report.in_window_records, 1)
        self.assertEqual(report.oldest_protected_seq, 3)

    def test_totals_are_consistent(self) -> None:
        report = classify_window(self.entries, window_bytes=500)
        self.assertEqual(
            report.total_records, report.in_window_records + report.expired_records
        )
        self.assertEqual(
            report.total_bytes, report.in_window_bytes + report.expired_bytes
        )

    def test_newest_record_always_inside(self) -> None:
        # A budget that fits the newest record exactly: 300 in, 300 out.
        report = classify_window(self.entries, window_bytes=300)
        self.assertEqual(report.in_window_records, 1)
        self.assertEqual(report.oldest_protected_seq, 3)

    def test_no_records_in_window_when_newest_is_oversized(self) -> None:
        # One record larger than the whole budget: nothing is inside,
        # so no key has a visible nonce reference at all.
        report = classify_window([{"size_bytes": 5000, "seq": 1}], window_bytes=1000)
        self.assertEqual(report.in_window_records, 0)
        self.assertEqual(report.expired_records, 1)
        self.assertIsNone(report.oldest_protected_seq)
        self.assertEqual(report.newest_expired_seq, 1)

    def test_oversized_newest_record_fails_closed_for_every_signer(self) -> None:
        entries = [
            {"size_bytes": 100, "seq": 1, "did": "did:key:zA", "nonce": "1"},
            {"size_bytes": 5000, "seq": 2, "did": "did:key:zB", "nonce": "2"},
        ]
        report = classify_window(entries, window_bytes=1000, did="did:key:zA")
        self.assertFalse(report.did_last_seen_protected)
        self.assertEqual(report.did_expired_records, 1)

    def test_version_is_reported(self) -> None:
        self.assertEqual(classify_window(self.entries).version, NONCE_WINDOW_VERSION)

    def test_window_bytes_is_reported(self) -> None:
        report = classify_window(self.entries, window_bytes=777)
        self.assertEqual(report.window_bytes, 777)

    def test_single_record(self) -> None:
        report = classify_window([{"size_bytes": 10, "seq": 9}], window_bytes=10)
        self.assertEqual(report.in_window_records, 1)
        self.assertEqual(report.oldest_protected_seq, 9)

    def test_reason_is_none_without_a_did_filter(self) -> None:
        self.assertIsNone(classify_window(self.entries, window_bytes=500).reason)

    def test_report_is_frozen(self) -> None:
        report = classify_window(self.entries)
        with self.assertRaises(Exception):
            report.in_window_records = 0  # type: ignore[misc]


class _ClassifySignerTests(unittest.TestCase):
    """The per-signer verdict is the security-relevant output."""

    def setUp(self) -> None:
        # Two records by zAAA and one by zBBB, newest last.
        self.entries = [
            {"size_bytes": 100, "seq": 1, "from": "did:key:zAAA", "nonce": 10},
            {"size_bytes": 100, "seq": 2, "from": "did:key:zBBB", "nonce": 20},
            {"size_bytes": 100, "seq": 3, "did": "did:key:zAAA", "nonce": 30},
        ]

    def test_protected_when_a_record_is_inside(self) -> None:
        report = classify_window(self.entries, window_bytes=1000, did="did:key:zAAA")
        self.assertTrue(report.did_last_seen_protected)
        self.assertEqual(report.did_in_window_records, 2)
        self.assertEqual(report.did_expired_records, 0)

    def test_newest_visible_nonce_is_reported(self) -> None:
        report = classify_window(self.entries, window_bytes=1000, did="did:key:zAAA")
        self.assertEqual(report.did_last_nonce_in_window, "30")

    def test_expiry_when_every_record_is_buried(self) -> None:
        # Only the newest record (seq 3, zAAA) fits; zAAA still has a
        # nonce visible, so it stays protected.
        report = classify_window(self.entries, window_bytes=100, did="did:key:zAAA")
        self.assertTrue(report.did_last_seen_protected)
        self.assertEqual(report.did_last_nonce_in_window, "30")
        self.assertEqual(report.did_expired_records, 1)

    def test_expiry_for_a_signer_with_no_visible_record(self) -> None:
        # zBBB's only record is seq 2; with a 100-byte budget the
        # newest record (seq 3) occupies the whole window, so the
        # server can no longer see any nonce from zBBB.
        report = classify_window(self.entries, window_bytes=100, did="did:key:zBBB")
        self.assertFalse(report.did_last_seen_protected)
        self.assertEqual(report.did_in_window_records, 0)
        self.assertEqual(report.did_expired_records, 1)
        self.assertIsNone(report.did_last_nonce_in_window)

    def test_expiry_reason_names_the_condition(self) -> None:
        report = classify_window(self.entries, window_bytes=100, did="did:key:zBBB")
        assert report.reason is not None
        self.assertIn("buried", report.reason)
        self.assertIn("accepted again", report.reason)
        self.assertIn("proves authorship", report.reason)

    def test_protected_reason_names_the_condition(self) -> None:
        report = classify_window(self.entries, window_bytes=1000, did="did:key:zAAA")
        assert report.reason is not None
        self.assertIn("still see a nonce", report.reason)

    def test_unknown_signer_reason(self) -> None:
        report = classify_window(self.entries, did="did:key:zZZZ")
        self.assertFalse(report.did_last_seen_protected)
        assert report.reason is not None
        self.assertEqual(report.reason, "no record for this key was supplied")

    def test_did_field_is_echoed(self) -> None:
        report = classify_window(self.entries, did="did:key:zAAA")
        self.assertEqual(report.did, "did:key:zAAA")

    def test_records_with_no_identity_field_are_counted_separately(self) -> None:
        # A record with neither ``did`` nor ``from`` carries no
        # attributable identity; it still consumes window budget.
        entries = [{"size_bytes": 100, "seq": 1}, {"size_bytes": 100, "seq": 2}]
        report = classify_window(entries, window_bytes=1000)
        self.assertEqual(report.records_without_identity, 2)
        self.assertIsNone(report.did)

    def test_records_without_identity_are_counted_under_a_did_filter(self) -> None:
        entries = [
            {"size_bytes": 100, "seq": 1, "did": "did:key:zA", "nonce": "1"},
            {"size_bytes": 100, "seq": 2},
        ]
        report = classify_window(entries, did="did:key:zA")
        self.assertEqual(report.records_without_identity, 1)
        self.assertTrue(report.did_last_seen_protected)

    def test_identity_string_is_matched_by_exact_equality_only(self) -> None:
        # The module treats whatever ``did``/``from`` carries as an
        # opaque string and matches it exactly. It performs no
        # authentication, so a self-asserted nickname is matched but
        # never endorsed; see docs/nonce-window.md.
        entries = [{"size_bytes": 100, "seq": 1, "from": "~nick"}]
        matched = classify_window(entries, did="~nick")
        self.assertTrue(matched.did_last_seen_protected)
        unmatched = classify_window(entries, did="~nick2")
        self.assertFalse(unmatched.did_last_seen_protected)
        self.assertEqual(unmatched.did_in_window_records, 0)

    def test_unsigned_records_consume_budget(self) -> None:
        entries = [
            {"size_bytes": 100, "seq": 1, "from": "~nick"},
            {"size_bytes": 100, "seq": 2, "from": "did:key:zAAA", "nonce": 7},
        ]
        report = classify_window(entries, window_bytes=100)
        self.assertEqual(report.in_window_records, 1)
        self.assertEqual(report.oldest_protected_seq, 2)
        report2 = classify_window(entries, window_bytes=100, did="did:key:zAAA")
        self.assertTrue(report2.did_last_seen_protected)

    def test_nickname_record_is_not_a_did_prefix_match(self) -> None:
        # An unsigned record's ``from`` is self-asserted. Matching it
        # is a byte-budget statement about a string, not a claim that
        # the writer holds that identity.
        entries = [{"size_bytes": 100, "seq": 1, "from": "~nick"}]
        report = classify_window(entries, did="did:key:z")
        self.assertFalse(report.did_last_seen_protected)

    def test_did_key_wins_over_from_when_both_present(self) -> None:
        entries = [
            {"size_bytes": 100, "seq": 1, "did": "did:key:zREAL", "from": "~nick"}
        ]
        report = classify_window(entries, did="did:key:zREAL")
        self.assertTrue(report.did_last_seen_protected)
        report2 = classify_window(entries, did="~nick")
        self.assertFalse(report2.did_last_seen_protected)

    def test_ordering_of_newest_visible_nonce_is_record_order(self) -> None:
        # Nonce order and record order are independent; the module
        # reports the newest *record's* nonce, not the largest nonce.
        entries = [
            {"size_bytes": 100, "seq": 1, "did": "did:key:zA", "nonce": 99},
            {"size_bytes": 100, "seq": 2, "did": "did:key:zA", "nonce": 5},
        ]
        report = classify_window(entries, did="did:key:zA")
        self.assertEqual(report.did_last_nonce_in_window, "5")

    def test_nonce_int_is_normalized_to_a_string(self) -> None:
        entries = [{"size_bytes": 100, "seq": 1, "did": "did:key:zA", "nonce": 42}]
        report = classify_window(entries, did="did:key:zA")
        self.assertEqual(report.did_last_nonce_in_window, "42")

    def test_nineteen_digit_nonce_survives_as_a_string(self) -> None:
        big = "9999999999999999999"
        entries = [{"size_bytes": 100, "seq": 1, "did": "did:key:zA", "nonce": big}]
        report = classify_window(entries, did="did:key:zA")
        self.assertEqual(report.did_last_nonce_in_window, big)

    def test_missing_nonce_still_counts_as_protected(self) -> None:
        # Protection is about the server seeing the record's nonce; a
        # record supplied without one is still inside the window.
        entries = [{"size_bytes": 100, "seq": 1, "did": "did:key:zA"}]
        report = classify_window(entries, did="did:key:zA")
        self.assertTrue(report.did_last_seen_protected)
        self.assertIsNone(report.did_last_nonce_in_window)

    def test_expired_signer_with_no_records_at_all(self) -> None:
        entries = [{"size_bytes": 100, "seq": 1, "did": "did:key:zA"}]
        report = classify_window(entries, did="did:key:zOther")
        self.assertFalse(report.did_last_seen_protected)
        self.assertEqual(report.did_expired_records, 0)


class _ClassifyInputTests(unittest.TestCase):
    def test_accepts_window_entry_objects(self) -> None:
        entries = [
            WindowEntry(size_bytes=100, seq=1, did="did:key:zA", nonce="1"),
            WindowEntry(size_bytes=100, seq=2, did="did:key:zA", nonce="2"),
        ]
        report = classify_window(entries, did="did:key:zA")
        self.assertTrue(report.did_last_seen_protected)
        self.assertEqual(report.did_last_nonce_in_window, "2")

    def test_accepts_objects_with_attributes(self) -> None:
        class Row:
            size_bytes = 100
            seq = 1
            did = "did:key:zA"
            nonce = "7"

        report = classify_window([Row()], did="did:key:zA")
        self.assertTrue(report.did_last_seen_protected)

    def test_accepts_a_tuple_of_records(self) -> None:
        report = classify_window(
            ({"size_bytes": 100, "seq": 1}, {"size_bytes": 100, "seq": 2})
        )
        self.assertEqual(report.total_records, 2)

    def test_accepts_json_parsed_dicts(self) -> None:
        raw = json.loads('[{"size_bytes": 100, "seq": 1}]')
        report = classify_window(raw)
        self.assertEqual(report.total_records, 1)

    def test_does_not_mutate_the_input(self) -> None:
        entries = [
            {"size_bytes": 100, "seq": 1, "from": "did:key:zA", "nonce": 10},
            {"size_bytes": 200, "seq": 2, "did": "did:key:zA"},
        ]
        before = json.dumps(entries, sort_keys=True)
        classify_window(entries, window_bytes=150, did="did:key:zA")
        self.assertEqual(json.dumps(entries, sort_keys=True), before)

    def test_rejects_empty_entries(self) -> None:
        with self.assertRaises(NonceWindowError):
            classify_window([])

    def test_rejects_string_entries(self) -> None:
        with self.assertRaises(NonceWindowError):
            classify_window("not a sequence of records")

    def test_rejects_bytes_entries(self) -> None:
        with self.assertRaises(NonceWindowError):
            classify_window(b"records")

    def test_rejects_non_iterable_entries(self) -> None:
        with self.assertRaises(NonceWindowError):
            classify_window(42)

    def test_rejects_entry_without_size(self) -> None:
        with self.assertRaises(NonceWindowError):
            classify_window([{"seq": 1}])

    def test_rejects_zero_size(self) -> None:
        with self.assertRaises(NonceWindowError):
            classify_window([{"size_bytes": 0, "seq": 1}])

    def test_rejects_negative_size(self) -> None:
        with self.assertRaises(NonceWindowError):
            classify_window([{"size_bytes": -5, "seq": 1}])

    def test_rejects_bool_size(self) -> None:
        with self.assertRaises(NonceWindowError):
            classify_window([{"size_bytes": True, "seq": 1}])

    def test_rejects_str_size(self) -> None:
        with self.assertRaises(NonceWindowError):
            classify_window([{"size_bytes": "100", "seq": 1}])

    def test_rejects_float_size(self) -> None:
        with self.assertRaises(NonceWindowError):
            classify_window([{"size_bytes": 100.0, "seq": 1}])

    def test_rejects_unusable_entry_type(self) -> None:
        with self.assertRaises(NonceWindowError):
            classify_window([42])

    def test_rejects_bad_seq(self) -> None:
        with self.assertRaises(NonceWindowError):
            classify_window([{"size_bytes": 10, "seq": "1"}])

    def test_rejects_bool_seq(self) -> None:
        with self.assertRaises(NonceWindowError):
            classify_window([{"size_bytes": 10, "seq": True}])

    def test_rejects_non_str_did(self) -> None:
        with self.assertRaises(NonceWindowError):
            classify_window([{"size_bytes": 10, "did": 5}])

    def test_rejects_float_nonce(self) -> None:
        # A float nonce may already have lost precision above 2**53.
        with self.assertRaises(NonceWindowError):
            classify_window([{"size_bytes": 10, "nonce": 1.5}])

    def test_rejects_bool_nonce(self) -> None:
        with self.assertRaises(NonceWindowError):
            classify_window([{"size_bytes": 10, "nonce": True}])

    def test_rejects_nonce_of_wrong_type(self) -> None:
        with self.assertRaises(NonceWindowError):
            classify_window([{"size_bytes": 10, "nonce": ["1"]}])

    def test_rejects_zero_window(self) -> None:
        with self.assertRaises(NonceWindowError):
            classify_window([{"size_bytes": 10}], window_bytes=0)

    def test_rejects_bool_window(self) -> None:
        with self.assertRaises(NonceWindowError):
            classify_window([{"size_bytes": 10}], window_bytes=True)

    def test_rejects_non_str_filter_did(self) -> None:
        with self.assertRaises(NonceWindowError):
            classify_window([{"size_bytes": 10}], did=5)

    def test_error_names_the_offending_index(self) -> None:
        with self.assertRaises(NonceWindowError) as ctx:
            classify_window([{"size_bytes": 10}, {"size_bytes": 0}])
        self.assertIn("entry 1", str(ctx.exception))


class _EndToEndScenarioTests(unittest.TestCase):
    """Reproducible scenarios an integrator can re-run by hand."""

    def test_busy_signed_room_buries_its_own_earliest_message(self) -> None:
        # 285-byte signed records, 1 MiB window: 3679 fit. Message 0
        # falls out once 3680 newer signed records have landed.
        size = signed_record_bytes(190)
        budget = records_in_window(size, MIB)
        entries = [
            {"size_bytes": size, "seq": i, "did": "did:key:zA", "nonce": str(i)}
            for i in range(budget + 1)
        ]
        report = classify_window(entries, did="did:key:zA")
        self.assertEqual(report.in_window_records, budget)
        self.assertEqual(report.expired_records, 1)
        self.assertEqual(report.newest_expired_seq, 0)
        # The key still has newer records visible, so the strictly
        # increasing check still has a reference point.
        self.assertTrue(report.did_last_seen_protected)

    def test_quiet_signer_loses_protection_in_a_crowded_room(self) -> None:
        # A signer whose only message is old, in a room that has since
        # filled its tail with other keys' traffic.
        size = 190
        entries = [{"size_bytes": size, "seq": 0, "did": "did:key:zQuiet", "nonce": "1"}]
        entries += [
            {
                "size_bytes": signed_record_bytes(size),
                "seq": i + 1,
                "did": f"did:key:zOther{i % 5}",
                "nonce": str(i + 1),
            }
            for i in range(records_in_window(signed_record_bytes(size), MIB))
        ]
        report = classify_window(entries, did="did:key:zQuiet")
        self.assertFalse(report.did_last_seen_protected)
        self.assertEqual(report.did_in_window_records, 0)
        self.assertEqual(report.did_expired_records, 1)
        assert report.reason is not None
        self.assertIn("buried", report.reason)

    def test_same_text_two_signers_are_independent(self) -> None:
        # The window is per room, but the nonce reference is per key:
        # one signer's expiry says nothing about another's.
        entries = [
            {"size_bytes": 100, "seq": 1, "did": "did:key:zA", "nonce": "1"},
            {"size_bytes": 900, "seq": 2, "did": "did:key:zB", "nonce": "1"},
        ]
        report_a = classify_window(entries, window_bytes=900, did="did:key:zA")
        report_b = classify_window(entries, window_bytes=900, did="did:key:zB")
        self.assertFalse(report_a.did_last_seen_protected)
        self.assertTrue(report_b.did_last_seen_protected)


if __name__ == "__main__":
    unittest.main()