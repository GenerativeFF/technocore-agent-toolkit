# Threat model — `technocore_verify`

This module is a pure verifier. It does not fetch, execute, or follow
any content from a signed payload; the signed payload itself is treated
as untrusted data.

## What this module guarantees

- **Key binding**: when a caller supplies a 32-byte public key, a
  `valid` result implies the signature was produced by the holder of
  that key over the canonical bytes reconstructed from the payload.
- **Integrity**: any change to `room`, `nonce`, or `text` (after
  sweep) breaks the signature and yields `valid=False`.
- **DID consistency**: when both `public_key` and the payload's `did`
  are present, a `valid` result implies they are consistent (the DID
  was derived from the supplied public key).
- **Determinism**: identical inputs yield identical outputs.

## What this module does **not** guarantee

- **Authority**: a valid signature proves key possession at signing
  time. It does not prove the signer is allowed to perform any action,
  is a real human, or controls any external resource.
- **Freshness**: the verifier does not check nonces against a
  history, only their shape.
- **Server trust**: nothing here implies the message was accepted by
  the network, stored, or relayed. The network is responsible for
  those concerns.
- **Origin privacy**: the verifier does not anonymise anything; the
  DID is reported verbatim so callers can audit.

## Adversaries considered

1. **Forger without the private key** — cannot produce a valid
   signature for any payload. Caught by Ed25519 verification.
2. **Forger who steals a key** — can sign as the legitimate DID until
   the key is rotated. The verifier cannot distinguish this from the
   legitimate signer. Mitigation is operational (key rotation, audit
   logs); not in scope for this module.
3. **Replay attacker** — can re-broadcast a previously signed
   payload. The verifier does not detect this; the caller is expected
   to track seen nonces per `(key, room)`.
4. **Truncation / tampering attacker** — any change to `room`,
   `nonce`, or `text` invalidates the signature. Caught.
5. **Malicious DID in payload** — if the caller supplies only
   `expected_did` (no `public_key`), the verifier derives the public
   key from the DID embedded in the payload and verifies the
   signature against that derived key. This is a weaker check than
   supplying an explicit `public_key` because the attacker controls
   the DID string. Callers that need strong binding must pass
   `public_key`.

## Caller responsibilities

- Pin the canonical reference (room, nonce, text) against an
  authoritative source before relying on a verified message.
- Maintain a per-`(key, room)` nonce set and reject already-seen
  nonces if replay protection is required.
- Treat DID mismatches between the payload and any pinned
  expectation as a hard failure (the verifier reports the reason).
- Never log the full payload if it might contain private material
  from the operator's downstream systems; log the `fingerprint` and
  verdict instead.

## Out of scope by design

- Cross-checking room membership or topic constraints.
- Decoding attachments, links, or commands inside `text`.
- Any network I/O, file I/O beyond argument parsing, or process
  invocation triggered by payload content.