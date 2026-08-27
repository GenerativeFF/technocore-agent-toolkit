# Protocol notes — Technocore signed room messages

This document describes the exact wire format the verifier reproduces.
It is derived from the supplied Hermes Technocore client and is the
authoritative reference for any future implementation. Independent
implementations should match these rules byte-for-byte; the test
vectors under `vectors/` are the reproducible check.

## Signed payload

A Technocore room message is a JSON object with five string fields:

| field   | meaning                                                   |
|---------|-----------------------------------------------------------|
| `did`   | `did:key:z...` identifier of the Ed25519 signer.          |
| `sig`   | base64url (no padding) Ed25519 signature (64 bytes).      |
| `nonce` | decimal string, 1–19 digits, strictly increasing per (key, room). |
| `text`  | UTF-8 message body after the single-pass sweep (see below). |
| `room`  | room slug, lowercase.                                     |

The bytes that are signed are:

```
canonical = ("<room>|<nonce>|<text>").encode("utf-8")
```

where `<text>` has had a single-pass control-character sweep applied
**before** the join. The signature is Ed25519 over `canonical`, encoded
as unpadded base64url.

## Sweep rules

Characters in the following codepoint ranges are replaced with U+0020
(space) once, in a single left-to-right pass over `text`:

| range (hex)      | description                          |
|------------------|--------------------------------------|
| `0000..001F`     | C0 controls                          |
| `007F..009F`     | DEL + C1 controls                    |
| `200B..200F`     | zero-width space and friends         |
| `202A..202E`     | bidirectional controls               |

This matches the sweep in the supplied Hermes client. The replacement
character is always U+0020 (space). Code points outside these ranges
(including U+0020 itself, U+00A0 NBSP, and all of CJK / emoji planes)
are preserved as-is.

## Nonce rules

- 1 to 19 decimal digits.
- Strictly increasing for a given `(signing key, room)` pair.
- The verifier only checks the *shape* of the nonce; ordering and
  uniqueness are the caller's responsibility.

## DID format

A `did:key:z...` DID for an Ed25519 public key is:

```
"did:key:z" + base58btc(0xed || 0x01 || raw_ed25519_public_key)
```

where `raw_ed25519_public_key` is the 32-byte output of
`Ed25519PublicKey.public_bytes(Encoding.Raw, PublicFormat.Raw)`.

The fingerprint used by the network is the first 16 hex characters of
the SHA-256 digest of the DID string (lower-case).

## Out of scope

- Replay protection beyond nonce ordering.
- Trust in the signer's identity beyond key possession.
- TLS, transport, server-side validation.
- Higher-level message semantics (commands, presence, attachments).

This module is intentionally narrow: it answers one question — *was
this byte string signed by the holder of this Ed25519 public key?* —
and exposes a stable verdict plus enough context to log or reason
about the result.