"""Signed-message verifier for the Technocore protocol.

Implements independent verification of Technocore signed room messages
without executing, fetching, or following any participant-supplied
content. Designed to be embedded by other tools that need to make
trust decisions based on cryptographic authorship.

Canonical signed payload
------------------------

Per the supplied Hermes Technocore client and protocol notes:

    payload_bytes = ("<room>|<nonce>|<text>").encode("utf-8")

where ``text`` has had a single-pass control-character sweep applied
(replace U+0000..U+001F, U+007F..U+009F, U+200B..U+200F, U+202A..U+202E
with U+0020). ``nonce`` is the decimal string used at sign time.
The signature is Ed25519 over ``payload_bytes`` and is encoded as
unpadded base64url. The DID format is ``did:key:z`` followed by the
base58btc encoding of the multicodec prefix ``0xed 0x01`` concatenated
with the 32-byte raw Ed25519 public key.

Security model
--------------

* The verifier is a pure function over its inputs. It performs no
  network I/O, file I/O beyond reading arguments, or process
  invocation.
* The verifier treats all input as untrusted data. A valid signature
  proves only possession of the Ed25519 private key corresponding to
  the claimed DID at the time of signing; it does not prove authority,
  identity-of-person, or truth of the message text.
* Pass ``public_key`` (the 32-byte raw Ed25519 public key) and/or
  ``expected_did`` to bind the result to a specific peer. When both
  are supplied, they must be consistent (the public key must hash to
  the DID's fingerprint).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
from dataclasses import dataclass
from typing import Mapping, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

# Multicodec prefix for ed25519-pub (0xed 0x01).
_ED25519_PUB_MULTICODEC = b"\xed\x01"

# Base58btc alphabet (Bitcoin/IPFS order).
_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

# Sweep ranges mirrored from the supplied client's ``sweep`` function.
# Replaced with U+0020 (space) before canonicalization.
_SWEEP_RANGES: tuple[tuple[int, int], ...] = (
    (0x0000, 0x0020),  # C0 controls + space
    (0x007F, 0x00A0),  # DEL + C1 controls
    (0x200B, 0x2010),  # zero-width and friends
    (0x202A, 0x202F),  # bidirectional controls
)


class VerifierError(ValueError):
    """Raised for malformed input that cannot be evaluated."""


@dataclass(frozen=True)
class VerifyResult:
    """Outcome of verifying a signed message.

    Attributes:
        valid: True only when the signature matched the supplied
            key/did and the reconstructed canonical payload.
        did: The DID extracted from the payload (always returned when
            the payload parses, for downstream logging).
        fingerprint: Lowercase hex SHA-256 prefix (16 hex chars) of
            the DID, when the DID was parseable.
        reason: Short human-readable explanation when ``valid`` is
            False. ``None`` when ``valid`` is True.
        canonical_sha256: Lowercase hex SHA-256 of the canonical
            payload bytes that were signed, when reconstruction
            succeeded. Useful for cross-tool debugging.
    """

    valid: bool
    did: Optional[str]
    fingerprint: Optional[str]
    reason: Optional[str]
    canonical_sha256: Optional[str]


def sweep(text: str) -> str:
    """Apply the protocol's single-pass control-character sweep.

    Mirrors ``sweep`` in the supplied Hermes client so that verifiers
    agree with signers on the canonical byte representation of
    ``text``. The replacement is always U+0020 (space).
    """
    out = []
    for ch in text:
        o = ord(ch)
        replaced = False
        for lo, hi in _SWEEP_RANGES:
            if lo <= o < hi:
                out.append(" ")
                replaced = True
                break
        if not replaced:
            out.append(ch)
    return "".join(out)


def _b64url_decode(data: str) -> bytes:
    """Strict unpadded base64url decode.

    Raises ``VerifierError`` if the input contains characters outside
    the base64url alphabet or has an invalid padding length.
    """
    if data is None:
        raise VerifierError("signature is missing")
    if not isinstance(data, str):
        raise VerifierError("signature must be a string")
    # Allow URL-safe alphabet plus standard base64 alphabet; reject
    # everything else. Padding is forbidden.
    allowed = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
    if any(c not in allowed for c in data):
        raise VerifierError("signature contains non-base64url characters")
    pad = (-len(data)) % 4
    try:
        return base64.urlsafe_b64decode(data + ("=" * pad))
    except Exception as exc:  # noqa: BLE001 - narrow surface at caller
        raise VerifierError(f"signature is not valid base64url: {exc}") from exc


def _b58encode(data: bytes) -> str:
    n = int.from_bytes(data, "big")
    out = []
    while n > 0:
        n, rem = divmod(n, 58)
        out.append(_B58_ALPHABET[rem])
    pad = 0
    for b in data:
        if b == 0:
            pad += 1
        else:
            break
    return ("1" * pad) + "".join(reversed(out) or "1")


def did_from_public_key(public_key: bytes) -> str:
    """Compute the ``did:key:`` string for a 32-byte Ed25519 public key."""
    if not isinstance(public_key, (bytes, bytearray)):
        raise VerifierError("public_key must be bytes")
    if len(public_key) != 32:
        raise VerifierError(f"public_key must be 32 bytes, got {len(public_key)}")
    return "did:key:z" + _b58encode(_ED25519_PUB_MULTICODEC + bytes(public_key))


def fingerprint_of(did: str) -> str:
    """Return the 16-hex-char SHA-256 prefix of a DID."""
    return hashlib.sha256(did.encode("utf-8")).hexdigest()[:16]


def _require(payload: Mapping[str, object], key: str) -> str:
    value = payload.get(key)
    if value is None:
        raise VerifierError(f"payload is missing required field: {key!r}")
    if not isinstance(value, str):
        raise VerifierError(f"payload field {key!r} must be a string")
    return value


def canonical_bytes(room: str, nonce: str, text: str) -> bytes:
    """Reconstruct the exact bytes that were signed.

    Sweeps ``text`` before joining, so the verifier agrees with
    conformant signers regardless of whether they pre-swept.
    """
    if not isinstance(room, str):
        raise VerifierError("room must be a string")
    if not isinstance(nonce, str):
        raise VerifierError("nonce must be a string")
    if not nonce:
        raise VerifierError("nonce must not be empty")
    if not (1 <= len(nonce) <= 19) or not nonce.isdigit():
        # Per the protocol notes: nonce is 1..19 decimal digits and
        # strictly increasing per (key, room). We only check the shape
        # here; ordering is the caller's responsibility.
        raise VerifierError(
            "nonce must be 1..19 decimal digits"
        )
    return f"{room}|{nonce}|{sweep(text)}".encode("utf-8")


def verify(
    payload: Mapping[str, object],
    public_key: Optional[bytes] = None,
    *,
    expected_did: Optional[str] = None,
) -> VerifyResult:
    """Verify a Technocore signed message.

    Args:
        payload: Mapping with fields ``did``, ``sig``, ``nonce``,
            ``text``, ``room``. All values must be strings.
        public_key: Optional 32-byte raw Ed25519 public key to verify
            against. When supplied alone, the DID is computed from
            it and must match ``payload["did"]`` if present.
        expected_did: Optional DID string that the signer must match.
            When supplied alone, the DID in ``payload`` must equal it.

    Returns:
        ``VerifyResult`` describing the outcome. ``valid`` is True
        only when all provided bindings agree and the Ed25519
        signature verifies over the canonical payload bytes.

    Raises:
        VerifierError: When the payload is structurally invalid and
            cannot be evaluated.
    """
    did = _require(payload, "did")
    sig_b64 = _require(payload, "sig")
    nonce = _require(payload, "nonce")
    text = _require(payload, "text")
    room = _require(payload, "room")

    if not did.startswith("did:key:z"):
        return VerifyResult(False, did, fingerprint_of(did),
                            "did must start with 'did:key:z'", None)

    fp = fingerprint_of(did)

    # Compute canonical bytes (and SHA) first so that downstream
    # failures still expose what was signed. Structural payload
    # errors raised here are surfaced as a failed VerifyResult
    # rather than VerifierError, because the payload did at least
    # parse as a mapping.
    try:
        canonical = canonical_bytes(room, nonce, text)
    except VerifierError as exc:
        return VerifyResult(False, did, fp, str(exc), None)
    canonical_sha = hashlib.sha256(canonical).hexdigest()

    sig_bytes = _b64url_decode(sig_b64)
    if len(sig_bytes) != 64:
        # Ed25519 signatures are always 64 bytes.
        return VerifyResult(False, did, fp,
                            f"signature length is {len(sig_bytes)}, expected 64",
                            canonical_sha)

    if public_key is not None:
        if not isinstance(public_key, (bytes, bytearray)) or len(public_key) != 32:
            raise VerifierError("public_key must be 32 bytes")
        key_did = did_from_public_key(bytes(public_key))
        if not hmac.compare_digest(key_did, did):
            return VerifyResult(False, did, fp,
                                f"public_key does not match did {did}", canonical_sha)

    if expected_did is not None:
        if not hmac.compare_digest(expected_did, did):
            return VerifyResult(False, did, fp,
                                f"did does not match expected {expected_did}",
                                canonical_sha)

    try:
        Ed25519PublicKey.from_public_bytes(
            bytes(public_key) if public_key is not None else _public_key_from_did(did)
        ).verify(sig_bytes, canonical)
    except InvalidSignature:
        return VerifyResult(False, did, fp,
                            "signature does not match canonical payload",
                            canonical_sha)
    except VerifierError as exc:
        return VerifyResult(False, did, fp, str(exc), canonical_sha)

    return VerifyResult(True, did, fp, None, canonical_sha)


def _public_key_from_did(did: str) -> bytes:
    """Extract the 32-byte raw public key from a ``did:key:z...`` string.

    Raises ``VerifierError`` if the DID is malformed or has the wrong
    multicodec prefix.
    """
    if not did.startswith("did:key:z"):
        raise VerifierError("did must start with 'did:key:z'")
    body = did[len("did:key:z"):]
    if not body:
        raise VerifierError("did body is empty")
    # Leading '1' chars represent leading 0x00 bytes in the original buffer.
    lz = 0
    while lz < len(body) and body[lz] == "1":
        lz += 1
    n = 0
    for ch in body[lz:]:
        idx = _B58_ALPHABET.find(ch)
        if idx < 0:
            raise VerifierError(f"did contains non-base58 character: {ch!r}")
        n = n * 58 + idx
    if n == 0:
        raw = b""
    else:
        size = (n.bit_length() + 7) // 8
        raw = n.to_bytes(size, "big")
    decoded = b"\x00" * lz + raw
    if len(decoded) < 34 or decoded[:2] != _ED25519_PUB_MULTICODEC:
        raise VerifierError("did is not an ed25519-pub did:key")
    return decoded[2:34]


__all__ = [
    "VerifyResult",
    "VerifierError",
    "canonical_bytes",
    "did_from_public_key",
    "fingerprint_of",
    "sweep",
    "verify",
]