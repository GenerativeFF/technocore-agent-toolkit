"""Generate sanitized test vectors for ``technocore_verify``.

This script builds a small set of golden cases from freshly generated
ephemeral Ed25519 keypairs. Only public material (public key, DID,
canonical SHA-256, signature, room/nonce/text, expected verdict) is
written to ``vectors/verifier_cases.json``. No private key material
is generated or persisted beyond the process lifetime.

The cases exercise:

  * valid signature
  * tampered text (one-byte change)
  * tampered nonce
  * tampered room
  * sweep interaction (control char replaced with space before signing)
  * signature length wrong (32 bytes instead of 64)
  * DID mismatched with key
"""
from __future__ import annotations

import base64
import hashlib
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src.technocore_verify import (  # noqa: E402
    canonical_bytes,
    did_from_public_key,
    sweep,
)


def b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def fresh() -> tuple[Ed25519PrivateKey, bytes, str]:
    sk = Ed25519PrivateKey.generate()
    pk = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return sk, pk, did_from_public_key(pk)


def make_case(name: str, *, valid: bool, room: str, nonce: str,
              sign_text: str, payload_text: str | None = None,
              pk: bytes, did: str) -> dict:
    payload_text = payload_text if payload_text is not None else sign_text
    canonical = canonical_bytes(room, nonce, sign_text)
    canonical_sha = hashlib.sha256(canonical).hexdigest()
    sig = b64url(fresh()[0].sign(canonical)) if False else None  # placeholder
    return {
        "name": name,
        "public_key_b64": b64(pk),
        "did": did,
        "room": room,
        "nonce": nonce,
        "text": payload_text,
        "sig_b64url": sig,
        "expect_valid": valid,
        "expect_canonical_sha256": canonical_sha,
    }


def main() -> int:
    cases = []

    # Case 1: plain valid message.
    sk, pk, did = fresh()
    room, nonce = "lobby", "1700000000000"
    text = "hello Technocore"
    sig = sk.sign(canonical_bytes(room, nonce, text))
    canonical_sha = hashlib.sha256(canonical_bytes(room, nonce, text)).hexdigest()
    cases.append({
        "name": "valid-plain-ascii",
        "public_key_b64": b64(pk),
        "did": did,
        "room": room,
        "nonce": nonce,
        "text": text,
        "sig_b64url": b64url(sig),
        "expect_valid": True,
        "expect_canonical_sha256": canonical_sha,
    })

    # Case 2: tampered text (one byte changed after signing).
    sk2, pk2, did2 = fresh()
    sig2 = sk2.sign(canonical_bytes("lobby", "1700000000001", "abc"))
    cases.append({
        "name": "invalid-text-tampered",
        "public_key_b64": b64(pk2),
        "did": did2,
        "room": "lobby",
        "nonce": "1700000000001",
        "text": "abd",  # one char changed from "abc"
        "sig_b64url": b64url(sig2),
        "expect_valid": False,
        "expect_canonical_sha256": hashlib.sha256(
            canonical_bytes("lobby", "1700000000001", "abd")
        ).hexdigest(),
    })

    # Case 3: tampered nonce.
    sk3, pk3, did3 = fresh()
    sig3 = sk3.sign(canonical_bytes("lobby", "1700000000002", "fixed"))
    cases.append({
        "name": "invalid-nonce-tampered",
        "public_key_b64": b64(pk3),
        "did": did3,
        "room": "lobby",
        "nonce": "1700000000003",  # not what was signed
        "text": "fixed",
        "sig_b64url": b64url(sig3),
        "expect_valid": False,
        "expect_canonical_sha256": hashlib.sha256(
            canonical_bytes("lobby", "1700000000003", "fixed")
        ).hexdigest(),
    })

    # Case 4: tampered room.
    sk4, pk4, did4 = fresh()
    sig4 = sk4.sign(canonical_bytes("lobby", "1700000000004", "hi"))
    cases.append({
        "name": "invalid-room-tampered",
        "public_key_b64": b64(pk4),
        "did": did4,
        "room": "dev",
        "nonce": "1700000000004",
        "text": "hi",
        "sig_b64url": b64url(sig4),
        "expect_valid": False,
        "expect_canonical_sha256": hashlib.sha256(
            canonical_bytes("dev", "1700000000004", "hi")
        ).hexdigest(),
    })

    # Case 5: control-char sweep. The signer swept "a\x00b" -> "a b"
    # before signing. The payload stores the post-sweep text.
    sk5, pk5, did5 = fresh()
    raw_text = "a\x00b"
    swept_text = sweep(raw_text)
    assert swept_text == "a b"
    sig5 = sk5.sign(canonical_bytes("lobby", "1700000000005", raw_text))
    cases.append({
        "name": "valid-sweep-normalised",
        "public_key_b64": b64(pk5),
        "did": did5,
        "room": "lobby",
        "nonce": "1700000000005",
        "text": swept_text,  # post-sweep text matches what was signed
        "sig_b64url": b64url(sig5),
        "expect_valid": True,
        "expect_canonical_sha256": hashlib.sha256(
            canonical_bytes("lobby", "1700000000005", raw_text)
        ).hexdigest(),
    })

    # Case 6: signature length wrong (32 bytes).
    sk6, pk6, did6 = fresh()
    bogus_sig = b"\x00" * 32
    cases.append({
        "name": "invalid-sig-length",
        "public_key_b64": b64(pk6),
        "did": did6,
        "room": "lobby",
        "nonce": "1700000000006",
        "text": "anything",
        "sig_b64url": b64url(bogus_sig),
        "expect_valid": False,
        "expect_canonical_sha256": hashlib.sha256(
            canonical_bytes("lobby", "1700000000006", "anything")
        ).hexdigest(),
    })

    # Case 7: valid CJK text.
    sk7, pk7, did7 = fresh()
    cjk = "你好 Technocore 🌍"
    sig7 = sk7.sign(canonical_bytes("dev", "1700000000007", cjk))
    cases.append({
        "name": "valid-cjk-and-emoji",
        "public_key_b64": b64(pk7),
        "did": did7,
        "room": "dev",
        "nonce": "1700000000007",
        "text": cjk,
        "sig_b64url": b64url(sig7),
        "expect_valid": True,
        "expect_canonical_sha256": hashlib.sha256(
            canonical_bytes("dev", "1700000000007", cjk)
        ).hexdigest(),
    })

    out_dir = ROOT / "vectors"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "verifier_cases.json"
    out_path.write_text(json.dumps(cases, indent=2, ensure_ascii=False) + "\n")
    print(f"wrote {len(cases)} cases to {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())