"""Unit tests for ``technocore_verify``.

All keys are generated in-memory by the tests. No private key
material is committed to the repository and no live network calls
are made.
"""
from __future__ import annotations

import base64
import json
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

import sys

# Allow ``python -m unittest`` from the repo root or any subdirectory.
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src.technocore_verify import (  # noqa: E402
    VerifyResult,
    VerifierError,
    canonical_bytes,
    did_from_public_key,
    fingerprint_of,
    sweep,
    verify,
)


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _fresh_keypair() -> tuple[Ed25519PrivateKey, bytes, str]:
    sk = Ed25519PrivateKey.generate()
    raw_pub = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return sk, raw_pub, did_from_public_key(raw_pub)


def _sign(sk: Ed25519PrivateKey, room: str, nonce: str, text: str) -> bytes:
    """Sign the canonical form, mirroring the supplied client's signer."""
    canonical = f"{room}|{nonce}|{sweep(text)}".encode("utf-8")
    return sk.sign(canonical)


class SweepTests(unittest.TestCase):
    def test_replaces_c0_controls(self):
        self.assertEqual(sweep("a\x00b\x01c"), "a b c")
        self.assertEqual(sweep("a\x1fb"), "a b")

    def test_replaces_c1_and_del(self):
        self.assertEqual(sweep("x\x7fy"), "x y")
        # U+0080 is in the C1 control range (0x7F..0x9F) and IS swept.
        self.assertEqual(sweep("x\x80y"), "x y")
        # U+00A0 (NBSP) is just past the C1 range and must be kept.
        self.assertEqual(sweep("x\xA0y"), "x\xA0y")

    def test_replaces_zero_width_and_bidi(self):
        self.assertEqual(sweep("a\u200bb"), "a b")
        self.assertEqual(sweep("a\u202Eb"), "a b")

    def test_keeps_printable(self):
        s = "Hello, world! 你好, 🌍 — 2026."
        self.assertEqual(sweep(s), s)


class CanonicalTests(unittest.TestCase):
    def test_canonical_shape(self):
        c = canonical_bytes("lobby", "123", "hi")
        self.assertEqual(c, b"lobby|123|hi")

    def test_canonical_sweeps_text(self):
        c = canonical_bytes("lobby", "123", "hi\x00x")
        self.assertEqual(c, b"lobby|123|hi x")

    def test_nonce_shape(self):
        with self.assertRaises(VerifierError):
            canonical_bytes("lobby", "", "x")
        with self.assertRaises(VerifierError):
            canonical_bytes("lobby", "0x1", "x")
        with self.assertRaises(VerifierError):
            canonical_bytes("lobby", "1" * 20, "x")


class DidTests(unittest.TestCase):
    def test_did_round_trip(self):
        sk, raw_pub, did = _fresh_keypair()
        self.assertTrue(did.startswith("did:key:z"))
        body = did[len("did:key:z"):]
        # Base58btc encoding of 34 bytes typically yields 46-48 chars.
        self.assertGreaterEqual(len(body), 44)
        self.assertLessEqual(len(body), 50)
        # Re-derive the public key from the DID.
        from src.technocore_verify import _public_key_from_did
        self.assertEqual(_public_key_from_did(did), raw_pub)
        self.assertEqual(fingerprint_of(did), fingerprint_of(did))

    def test_did_from_bad_length(self):
        with self.assertRaises(VerifierError):
            did_from_public_key(b"\x00" * 31)


class VerifyTests(unittest.TestCase):
    def setUp(self):
        self.sk, self.pk, self.did = _fresh_keypair()

    def _payload(self, *, room="lobby", nonce="1700000000000", text="hello",
                 sig=None, did=None) -> dict:
        sig_b = sig if sig is not None else _sign(self.sk, room, nonce, text)
        return {
            "did": did if did is not None else self.did,
            "sig": _b64url(sig_b),
            "nonce": nonce,
            "text": text,
            "room": room,
        }

    def test_valid_signature_with_public_key(self):
        result = verify(self._payload(), public_key=self.pk)
        self.assertTrue(result.valid)
        self.assertEqual(result.did, self.did)
        self.assertEqual(result.fingerprint, fingerprint_of(self.did))
        self.assertIsNone(result.reason)
        self.assertEqual(len(result.canonical_sha256), 64)

    def test_valid_signature_with_expected_did(self):
        result = verify(self._payload(), expected_did=self.did)
        self.assertTrue(result.valid)

    def test_tampered_text_invalid(self):
        good = self._payload()
        tampered = dict(good)
        tampered["text"] = good["text"] + " "
        result = verify(tampered, public_key=self.pk)
        self.assertFalse(result.valid)
        self.assertIn("signature", (result.reason or "").lower())

    def test_tampered_nonce_invalid(self):
        good = self._payload()
        tampered = dict(good)
        tampered["nonce"] = str(int(good["nonce"]) + 1)
        result = verify(tampered, public_key=self.pk)
        self.assertFalse(result.valid)

    def test_tampered_room_invalid(self):
        good = self._payload()
        tampered = dict(good)
        tampered["room"] = "other-room"
        result = verify(tampered, public_key=self.pk)
        self.assertFalse(result.valid)

    def test_wrong_public_key_invalid(self):
        _, other_pk, _ = _fresh_keypair()
        result = verify(self._payload(), public_key=other_pk)
        self.assertFalse(result.valid)
        self.assertIn("does not match did", result.reason or "")

    def test_did_mismatch_invalid(self):
        result = verify(self._payload(), expected_did="did:key:zBogus")
        self.assertFalse(result.valid)
        self.assertIn("does not match expected", result.reason or "")

    def test_malformed_payload_raises(self):
        with self.assertRaises(VerifierError):
            verify({"did": self.did}, public_key=self.pk)
        with self.assertRaises(VerifierError):
            verify(self._payload() | {"sig": "@@@"})

    def test_signature_length_invalid(self):
        payload = self._payload(sig=b"\x00" * 32)
        result = verify(payload, public_key=self.pk)
        self.assertFalse(result.valid)
        self.assertIn("length", (result.reason or "").lower())

    def test_did_prefix_invalid(self):
        payload = self._payload(did="did:example:1234")
        result = verify(payload, public_key=self.pk)
        self.assertFalse(result.valid)
        self.assertIn("did:key:z", result.reason or "")

    def test_determinism(self):
        payload = self._payload()
        r1 = verify(payload, public_key=self.pk)
        r2 = verify(payload, public_key=self.pk)
        self.assertEqual(r1, r2)


class VectorTests(unittest.TestCase):
    """Run the deterministic golden vectors under vectors/verifier_cases.json.

    Vectors are sanitized: each was generated locally from a freshly
    created ephemeral Ed25519 keypair, and only the public key, the
    expected DID, the canonical SHA-256, and the verdict appear.
    """

    def test_vectors(self):
        path = ROOT / "vectors" / "verifier_cases.json"
        if not path.exists():
            self.skipTest(f"missing vectors file: {path}")
        cases = json.loads(path.read_text())
        self.assertTrue(cases, "vectors file is empty")
        for case in cases:
            with self.subTest(case=case.get("name")):
                pk = base64.b64decode(case["public_key_b64"])
                payload = {
                    "did": case["did"],
                    "sig": case["sig_b64url"],
                    "nonce": case["nonce"],
                    "text": case["text"],
                    "room": case["room"],
                }
                result = verify(
                    payload,
                    public_key=pk,
                    expected_did=case["did"],
                )
                self.assertEqual(
                    result.valid, case["expect_valid"],
                    f"case={case.get('name')} reason={result.reason}",
                )
                if case.get("expect_canonical_sha256"):
                    self.assertEqual(
                        result.canonical_sha256, case["expect_canonical_sha256"]
                    )


if __name__ == "__main__":
    unittest.main()