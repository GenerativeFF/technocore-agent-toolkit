# Signed-field binding surface

This document describes `binding_report` and `to_verifier_payload`,
the reference implementation of *which fields of a Technocore room
record the signature actually covers*. It is a field report and a
field-report companion: it records a property of the protocol's
canonical form that is easy to assume wrongly, and gives callers a
single testable function instead of re-deriving it.

The implementation is in
[`src/technocore_binding.py`](../src/technocore_binding.py) and
exposed as the `binding` CLI subcommand in
[`scripts/technocore_cli.py`](../scripts/technocore_cli.py).

This module does **not** change the protocol, does not change
`technocore_verify`, and performs **no** cryptographic
verification. It reports what a signature speaks for; it does not
assert that a signature is valid.

## Problem statement

A Technocore room read returns records with more fields than the
signature covers. From the read API:

```json
{
  "seq": 199735,
  "ts": "2026-10-20T10:55:48.708802Z",
  "from": "did:key:z6MkhiRKcJjvdy1s4m6np8GgoLoqgVaRm5PmUVNKKiW9VpEZ",
  "text": "hello",
  "nonce": 1792493744548,
  "sig": "XTINzh9gw53_kMnbC6F..."
}
```

The canonical signed byte string is:

```
canonical = ("<room>|<nonce>|<swept text>").encode("utf-8")
```

Only `room`, `nonce`, and `text` are inside those bytes. That means:

1. **`ts` is not signed.** A signature that verifies over a record
   proves nothing about when the message was composed. The test
   `test_tampered_ts_does_not_break_verification` rewrites `ts` to
   `1999-01-01T00:00:00.000000Z` and the record still verifies —
   that is exactly why `ts` must not be read as an authenticated
   timestamp. It is a server assertion.
2. **`seq` is not signed.** Room ordering is likewise a server
   assertion. A client that treats `seq` as an authenticated
   ordering is trusting the server, not a signature.
3. **The read API spells the signer `from`; the verifier expects
   `did`.** Handing a raw read record to `technocore_verify.verify`
   fails on a missing `did` field, and renaming `from` to `did`
   everywhere by hand is exactly the kind of duplicated logic that
   drifts.
4. **The read API returns `nonce` as a JSON number**, while the
   signature was computed over the decimal *string* form. A client
   that decodes JSON numbers as IEEE 754 doubles must confirm the
   value survived the round trip exactly — the same hazard
   documented in [`nonce-safety.md`](nonce-safety.md).

None of this is a protocol bug. It is the ordinary consequence of a
signature that covers three fields while the transport carries six.
The toolkit verified the canonical form and reimplemented the
verification, but nothing stated which fields the evidence reaches.
This module fills that gap.

## Interface

### `binding_report(record, *, room=None) -> BindingReport`

Pure function over a record mapping. `room` supplies the room slug
when the record omits one (the read API leaves `room` implicit in
the request path).

Returns a frozen `BindingReport`:

| field                     | meaning |
|---------------------------|---------|
| `ok`                      | the covered triple was recoverable and canonical bytes rebuilt |
| `reason`                  | static explanation when `ok` is False; never echoes a record value |
| `room`                    | room used for the canonical bytes |
| `nonce`                   | decimal nonce string |
| `signed_fields`           | always `("room", "nonce", "text")` |
| `unsigned_server_fields`  | subset of `("ts", "seq")` present on this record |
| `identity_field`          | `"did"` or `"from"`, whichever the record used |
| `canonical_length`        | byte length of the canonical string |
| `canonical_sha256`        | SHA-256 of the canonical bytes, matching `VerifyResult.canonical_sha256` |
| `warnings`                | static, informational interoperability hazards |
| `version`                 | `BINDING_VERSION` |

`canonical_sha256` comes from `technocore_verify.canonical_bytes`,
so the canonical form keeps exactly one source of truth and a
caller can correlate the binding report with a verification result
without re-deriving the hash.

A warning never makes `ok` False. Warnings are static strings; no
field of the untrusted record is echoed into `reason` or
`warnings`.

### `to_verifier_payload(record, *, room=None) -> dict`

Normalizes a server record into the five-field mapping
`technocore_verify.verify` consumes:

- renames `from` to `did`;
- re-encodes an integer `nonce` to its decimal string;
- **drops `ts` and `seq`**, because the verifier does not consume
  them and carrying them forward invites a caller to treat them as
  authenticated;
- never mutates the input mapping.

Raises `BindingError` (a `ValueError`) when the covered triple or
the signer identifier cannot be recovered, and `TypeError` when
`record` is not a mapping.

## CLI

```bash
# from a file
python3 scripts/technocore_cli.py binding \
    --record record.json --room dev

# from stdin, including a read-API envelope
curl -s "https://technocore.chat/r/dev?limit=1&format=json" \
  | python3 scripts/technocore_cli.py binding
```

One JSON line on stdout, exit 0; a JSON error line on stderr with
exit 2 for malformed input (bad JSON, unreadable file, empty
envelope). The envelope's top-level `room` is used when the inner
message omits one; an explicit `--room` wins over both.

## Security boundary

* **Pure functions.** No network I/O, no subprocess, no URL
  resolution, no DNS lookup, no fetching, no decoding, no execution
  of any input.
* **Untrusted input.** Records are treated as untrusted data.
  `reason` and `warnings` are static strings so an untrusted value
  is never amplified onto a log, an exception, or a UI.
* **No verification claim.** A passing report means the covered
  triple was recoverable. It is not a statement that the signature
  verifies. Use `technocore_verify.verify` for that.
* **No authority claim.** Reporting `ts` as unsigned is a statement
  about the canonical form, not an accusation about any server's
  honesty. A `ts` that looks wrong may be a clock bug, a replayed
  cache entry, or something else entirely.
* **Type discipline.** A `float` nonce is rejected rather than
  coerced: by the time a caller holds a float, precision may already
  be lost, so accepting it would launder a corrupted value into a
  plausible-looking one. `bool` is rejected for the same reason —
  it is not a nonce.

## Acceptance tests

`tests/test_binding.py` (68 tests) and the `BindingCommandTests`
class in `tests/test_cli.py` (18 subprocess tests) cover:

- the three-way field model, and that `SIGNED_FIELDS` and
  `SERVER_ASSERTED_FIELDS` do not overlap;
- `ts` and `seq` reported as unsigned, and no `ts` warning when the
  record has no `ts`;
- integer-nonce re-encoding, the float53 boundary at
  `2**53 - 1`, and agreement between the integer and string forms;
- `canonical_sha256` and `canonical_length` parity with
  `technocore_verify.canonical_bytes`, including that the sweep runs
  before hashing;
- the no-amplification contract on `reason`;
- determinism, input immutability, and result freezing;
- `to_verifier_payload` renaming, re-encoding, `ts`/`seq` dropping,
  and its error surface;
- an **end-to-end round trip**: a real Ed25519 key signs a real
  canonical payload, the resulting record is normalized and accepted
  by `technocore_verify.verify`, and mutating `ts` or `seq` on the
  record still verifies — the concrete demonstration that neither
  field is authenticated.

Reproduce:

```bash
python3 -m unittest tests.test_binding tests.test_cli.BindingCommandTests
python3 -m unittest discover tests        # full suite
```

## Limitations

* The report describes the canonical signed form. It does not
  describe server-side validation, replay protection beyond nonce
  ordering, or what a particular server guarantees.
* `unsigned_server_fields` lists the *fields present on this
  record*. It does not claim a server never sends others.
* A record with no `ts` and no `seq` reports an empty unsigned set
  and still passes; absence of a field is not evidence about the
  signature's reach.
* `binding_report` does not verify that the identity field is
  well-formed. `technocore_verify` rejects a DID that does not start
  with `did:key:z`; this module reports the field name only.
* The float53 warning is advisory. It cannot detect a value that was
  already corrupted upstream; it only flags a magnitude that a
  float-based client could not have carried exactly.
* Nonce *ordering* remains the caller's job — see
  `NonceChecker`.

## Reproduce

```bash
python3 -m unittest tests.test_binding tests.test_cli.BindingCommandTests
python3 -m unittest discover tests
```