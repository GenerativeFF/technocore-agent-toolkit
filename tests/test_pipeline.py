"""Integration test for the full verification pipeline.

This test exercises the layered pipeline described in
``docs/pipeline.md`` end-to-end:

    1. Signature shape check  (technocore_sig_shape)
    2. Nonce shape check      (technocore_nonce)
    3. Nonce history check    (technocore_nonce.NonceChecker)
    4. Safety scan            (technocore_scanner)
    5. Duplicate-form fold    (technocore_dupe_form)
    6. Signature verify       (technocore_verify)

All keys are generated in-memory by the tests. No private key
material is committed to the repository and no live network calls
are made.
"""
from __future__ import annotations

import base64
import sys
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src.technocore_dupe_form import dupe_form  # noqa: E402
from src.technocore_nonce import (  # noqa: E402
    NonceCheckResult,
    NonceChecker,
)
from src.technocore_scanner import ScanResult, scan  # noqa: E402
from src.technocore_sig_shape import (  # noqa: E402
    SigShapeResult,
    is_canonical_signature_shape,
    validate_signature_shape,
)
from src.technocore_sweep import sweep  # noqa: E402
from src.technocore_verify import (  # noqa: E402
    VerifyResult,
    canonical_bytes,
    did_from_public_key,
    verify,
)


# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------

def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _fresh_keypair() -> tuple[Ed25519PrivateKey, bytes, str]:
    sk = Ed25519PrivateKey.generate()
    raw_pub = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return sk, raw_pub, did_from_public_key(raw_pub)


def _sign_payload(
    sk: Ed25519PrivateKey,
    room: str,
    nonce: str,
    text: str,
) -> dict:
    """Sign a payload and return a JSON-shaped dict.

    Mirrors the supplied Hermes client's signer: the bytes that
    are signed are ``f"{room}|{nonce}|{sweep(text)}"``.
    """
    canonical = f"{room}|{nonce}|{sweep(text)}".encode("utf-8")
    sig = sk.sign(canonical)
    raw_pub = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    did = did_from_public_key(raw_pub)
    return {
        "did": did,
        "sig": _b64url(sig),
        "nonce": nonce,
        "text": text,
        "room": room,
    }


def _run_pipeline(
    payload: dict,
    public_key: bytes,
    checker: NonceChecker,
) -> dict:
    """Run the six-stage pipeline and return a structured verdict.

    Returns a dict with:

        ``valid``     - True only when every stage passed.
        ``stages``    - tuple of (stage_name, result) pairs.
        ``rejected``  - name of the first stage that failed,
                        or None when every stage passed.

    The function never raises for malformed payloads; it returns
    a structured failure instead. This matches the documented
    failure-handling contract in ``docs/pipeline.md``.
    """
    stages: list = []

    # Stage 1: signature shape
    sig_b64 = payload.get("sig", "")
    shape: SigShapeResult = validate_signature_shape(sig_b64)
    stages.append(("sig_shape", shape))
    if not shape.valid:
        return {
            "valid": False,
            "stages": tuple(stages),
            "rejected": "sig_shape",
        }

    # Stage 2: nonce shape (1..19 decimal digits, positive integer)
    nonce_str = payload.get("nonce", "")
    if not (1 <= len(nonce_str) <= 19) or not nonce_str.isdigit():
        nonce_shape = NonceCheckResult(False, "nonce must be 1..19 decimal digits")
    elif int(nonce_str) <= 0:
        nonce_shape = NonceCheckResult(False, "nonce must be positive")
    else:
        nonce_shape = NonceCheckResult(True)
    stages.append(("nonce_shape", nonce_shape))
    if not nonce_shape.valid:
        return {
            "valid": False,
            "stages": tuple(stages),
            "rejected": "nonce_shape",
        }

    # Stage 3: nonce history (strictly increasing per (did, room))
    history = checker.check_and_update(
        payload.get("did", ""),
        payload.get("room", ""),
        nonce_str,
    )
    stages.append(("nonce_history", history))
    if not history.valid:
        return {
            "valid": False,
            "stages": tuple(stages),
            "rejected": "nonce_history",
        }

    # Stage 4: safety scan
    text = payload.get("text", "")
    scan_result: ScanResult = scan(text)
    stages.append(("scan", scan_result))
    if not scan_result.safe:
        return {
            "valid": False,
            "stages": tuple(stages),
            "rejected": "scan",
        }

    # Stage 5: duplicate-form fold (always succeeds for a string)
    folded = dupe_form(text)
    stages.append(("dupe_form", folded))

    # Stage 6: signature verify
    verify_result: VerifyResult = verify(payload, public_key=public_key)
    stages.append(("verify", verify_result))
    if not verify_result.valid:
        return {
            "valid": False,
            "stages": tuple(stages),
            "rejected": "verify",
        }

    return {
        "valid": True,
        "stages": tuple(stages),
        "rejected": None,
    }


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------

class HappyPathTests(unittest.TestCase):
    """A well-formed payload passes every stage."""

    def test_full_pipeline_passes(self):
        sk, raw_pub, _ = _fresh_keypair()
        payload = _sign_payload(
            sk,
            room="dev",
            nonce="1792300600000",
            text="hello world",
        )
        checker = NonceChecker()
        verdict = _run_pipeline(payload, raw_pub, checker)

        self.assertTrue(
            verdict["valid"],
            f"pipeline rejected well-formed payload at stage "
            f"{verdict['rejected']!r}: {verdict['stages']}",
        )
        self.assertIsNone(verdict["rejected"])

        stage_names = tuple(name for name, _ in verdict["stages"])
        self.assertEqual(
            stage_names,
            ("sig_shape", "nonce_shape", "nonce_history",
             "scan", "dupe_form", "verify"),
        )

    def test_full_pipeline_with_cjk_text(self):
        sk, raw_pub, _ = _fresh_keypair()
        payload = _sign_payload(
            sk,
            room="dev",
            nonce="1792300600001",
            text="你好，世界 🌍",
        )
        checker = NonceChecker()
        verdict = _run_pipeline(payload, raw_pub, checker)
        self.assertTrue(verdict["valid"], verdict)

    def test_duplicate_form_fold_is_stable(self):
        # The fold must be a fixed point: re-folding the folded
        # form yields the same string.
        sk, raw_pub, _ = _fresh_keypair()
        text = "Việt  Việt   VIET"
        payload = _sign_payload(
            sk,
            room="dev",
            nonce="1792300600002",
            text=text,
        )
        checker = NonceChecker()
        verdict = _run_pipeline(payload, raw_pub, checker)
        self.assertTrue(verdict["valid"], verdict)

        folded = dupe_form(text)
        self.assertEqual(dupe_form(folded), folded)

    def test_pipeline_reaches_verify_with_consistent_did(self):
        sk, raw_pub, did = _fresh_keypair()
        payload = _sign_payload(
            sk,
            room="dev",
            nonce="1792300600003",
            text="another message",
        )
        self.assertEqual(payload["did"], did)
        checker = NonceChecker()
        verdict = _run_pipeline(payload, raw_pub, checker)
        self.assertTrue(verdict["valid"], verdict)


# ---------------------------------------------------------------------------
# Failure modes
# ---------------------------------------------------------------------------

class FailureModeTests(unittest.TestCase):
    """Each stage rejects the failure it is responsible for."""

    def test_malformed_signature_caught_at_stage_1(self):
        sk, raw_pub, _ = _fresh_keypair()
        payload = _sign_payload(
            sk,
            room="dev",
            nonce="1792300600010",
            text="hello",
        )
        # Truncate the signature to a length that is not 86.
        payload["sig"] = payload["sig"][:80]
        checker = NonceChecker()
        verdict = _run_pipeline(payload, raw_pub, checker)

        self.assertFalse(verdict["valid"])
        self.assertEqual(verdict["rejected"], "sig_shape")
        # Cheap pre-filter; cryptographic stages must NOT have run.
        rejected_names = {name for name, _ in verdict["stages"]}
        self.assertNotIn("verify", rejected_names)

    def test_signature_with_invalid_tail_char_caught_at_stage_1(self):
        sk, raw_pub, _ = _fresh_keypair()
        payload = _sign_payload(
            sk,
            room="dev",
            nonce="1792300600011",
            text="hello",
        )
        # Replace the last char with one that is not in {A, Q, g, w}.
        sig = payload["sig"]
        # Find a tail char that is not in TAIL_CHARS.
        replacement = "B"  # 'B' is in the base64url alphabet but
        #                    has a 6-bit value of 1, which means
        #                    the trailing byte is not divisible by 4.
        self.assertNotIn(replacement, ("A", "Q", "g", "w"))
        payload["sig"] = sig[:-1] + replacement
        checker = NonceChecker()
        verdict = _run_pipeline(payload, raw_pub, checker)

        self.assertFalse(verdict["valid"])
        self.assertEqual(verdict["rejected"], "sig_shape")

    def test_bad_nonce_shape_caught_at_stage_2(self):
        sk, raw_pub, _ = _fresh_keypair()
        payload = _sign_payload(
            sk,
            room="dev",
            nonce="not-a-number",
            text="hello",
        )
        checker = NonceChecker()
        verdict = _run_pipeline(payload, raw_pub, checker)

        self.assertFalse(verdict["valid"])
        self.assertEqual(verdict["rejected"], "nonce_shape")
        rejected_names = {name for name, _ in verdict["stages"]}
        self.assertNotIn("verify", rejected_names)

    def test_zero_nonce_caught_at_stage_2(self):
        sk, raw_pub, _ = _fresh_keypair()
        payload = _sign_payload(
            sk,
            room="dev",
            nonce="0",
            text="hello",
        )
        checker = NonceChecker()
        verdict = _run_pipeline(payload, raw_pub, checker)

        self.assertFalse(verdict["valid"])
        self.assertEqual(verdict["rejected"], "nonce_shape")

    def test_replay_caught_at_stage_3(self):
        sk, raw_pub, _ = _fresh_keypair()
        first = _sign_payload(
            sk,
            room="dev",
            nonce="1792300600020",
            text="first message",
        )
        replay = _sign_payload(
            sk,
            room="dev",
            nonce="1792300600020",
            text="first message",
        )
        checker = NonceChecker()
        verdict_first = _run_pipeline(first, raw_pub, checker)
        self.assertTrue(verdict_first["valid"], verdict_first)

        verdict_replay = _run_pipeline(replay, raw_pub, checker)
        self.assertFalse(verdict_replay["valid"])
        self.assertEqual(verdict_replay["rejected"], "nonce_history")
        rejected_names = {name for name, _ in verdict_replay["stages"]}
        self.assertNotIn("verify", rejected_names)

    def test_hazardous_text_caught_at_stage_4(self):
        sk, raw_pub, _ = _fresh_keypair()
        # Shell metacharacter; the scanner flags 'shell' at 'high'.
        payload = _sign_payload(
            sk,
            room="dev",
            nonce="1792300600030",
            text="run `rm -rf /`",
        )
        checker = NonceChecker()
        verdict = _run_pipeline(payload, raw_pub, checker)

        self.assertFalse(verdict["valid"])
        self.assertEqual(verdict["rejected"], "scan")
        rejected_names = {name for name, _ in verdict["stages"]}
        self.assertNotIn("verify", rejected_names)

    def test_tampered_text_caught_at_stage_6(self):
        sk, raw_pub, _ = _fresh_keypair()
        payload = _sign_payload(
            sk,
            room="dev",
            nonce="1792300600040",
            text="original message",
        )
        # Tamper with the text after signing.
        payload["text"] = "tampered message"

        checker = NonceChecker()
        verdict = _run_pipeline(payload, raw_pub, checker)

        self.assertFalse(verdict["valid"])
        self.assertEqual(verdict["rejected"], "verify")
        verify_result = dict(verdict["stages"])[
            "verify" if "verify" in {n for n, _ in verdict["stages"]}
            else next(n for n, _ in verdict["stages"] if n == "verify")
        ]
        # The cryptographic check is the decisive stage; the
        # cheaper stages must have already passed.
        self.assertFalse(verify_result.valid)
        self.assertIn("signature", (verify_result.reason or "").lower())

    def test_wrong_public_key_caught_at_stage_6(self):
        sk, _wrong_pub, _ = _fresh_keypair()
        _other_sk, other_pub, _ = _fresh_keypair()
        payload = _sign_payload(
            sk,
            room="dev",
            nonce="1792300600050",
            text="hello",
        )
        checker = NonceChecker()
        verdict = _run_pipeline(payload, other_pub, checker)

        self.assertFalse(verdict["valid"])
        self.assertEqual(verdict["rejected"], "verify")


# ---------------------------------------------------------------------------
# Composition invariants
# ---------------------------------------------------------------------------

class CompositionInvariantTests(unittest.TestCase):
    """The pipeline composition must be internally consistent."""

    def test_canonical_bytes_match_verifier(self):
        sk, raw_pub, _ = _fresh_keypair()
        nonce = "1792300600060"
        text = "hello"
        room = "dev"
        payload = _sign_payload(sk, room=room, nonce=nonce, text=text)

        # The verifier's canonical_bytes must match the bytes the
        # helper signed. If they ever diverge, the integration is
        # broken regardless of what any other stage says.
        expected = canonical_bytes(room, nonce, sweep(text))
        self.assertEqual(expected, f"{room}|{nonce}|{sweep(text)}".encode("utf-8"))

        result = verify(payload, public_key=raw_pub)
        self.assertTrue(result.valid, result)

    def test_signature_shape_pre_filter_runs_before_crypto(self):
        # The cheap pre-filter must not require the cryptographic
        # check; if the shape is wrong, we should never have to
        # call into cryptography.hazmat.
        bad = "not-a-signature-at-all"
        self.assertFalse(is_canonical_signature_shape(bad))
        result = validate_signature_shape(bad)
        self.assertFalse(result.valid)
        self.assertIsNotNone(result.reason)

    def test_every_module_is_pure(self):
        # Smoke test: re-running the pipeline on the same input
        # must yield the same verdict. This catches accidental
        # introduction of process-wide state in any module.
        sk, raw_pub, _ = _fresh_keypair()
        payload = _sign_payload(
            sk,
            room="dev",
            nonce="1792300600070",
            text="deterministic message",
        )
        checker1 = NonceChecker()
        checker2 = NonceChecker()
        v1 = _run_pipeline(payload, raw_pub, checker1)
        v2 = _run_pipeline(payload, raw_pub, checker2)
        self.assertEqual(v1["valid"], v2["valid"])
        self.assertEqual(v1["rejected"], v2["rejected"])


if __name__ == "__main__":
    unittest.main()
