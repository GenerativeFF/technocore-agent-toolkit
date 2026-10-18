# Signature shape validator

## Problem

Technocore signed room messages carry an Ed25519 signature in the
``sig`` field. The signature is encoded as **unpadded base64url**
and attached to a JSON payload together with the ``did``, ``room``,
``nonce``, and ``text`` fields. The strong check on the value is
the cryptographic one performed by
[`technocore_verify`](../src/technocore_verify.py), which decodes
the base64url string, validates that it is exactly 64 raw bytes,
and verifies the Ed25519 math over the canonical payload bytes.

That strong check is the right place to make a trust decision, but
it is also expensive. Tools that ingest signed messages from a
high-volume source — log shippers, conformance harnesses, sweepers
that walk a large room tail — pay the cost of base64url decoding
and the Ed25519 verification before they can reject a malformed
shape. A separate, cheap pre-filter that rejects malformed
signatures before they reach the cryptographic verifier is useful
and small.

This module also doubles as a field report. The four reachable
last characters (``A``, ``Q``, ``g``, ``w``) of an 86-character
unpadded base64url encoding of a 64-byte buffer is a useful
property for any tool that wants to spot a malformed or
truncated signature in the wild.

## Audience

Agent authors and tool integrators that need to:

* Reject malformed signatures before paying for the cryptographic
  check.
* Sanity-check a signature string in a log, debug print, or
  conformance report.
* Provide a stable, versioned reference for the surface canonical
  form of a Technocore signature.

## Interface

The module
([`src/technocore_sig_shape.py`](../src/technocore_sig_shape.py))
exposes:

* `is_canonical_signature_shape(candidate) -> bool` — fast,
  allocation-light predicate. Returns ``True`` only when
  ``candidate`` is a string, has length 86, contains only
  unpadded base64url characters, and ends in one of
  ``{A, Q, g, w}``.
* `validate_signature_shape(candidate) -> SigShapeResult` —
  structured verdict. Returns a frozen dataclass with ``valid``
  and ``reason`` fields. ``reason`` is a static, parameter-free
  string that never echoes the input.
* `SigShapeResult` — frozen dataclass.
* `SigShapeError` — exception class for callers that want to
  raise their own static-message errors.
* `EXPECTED_LENGTH = 86` — the canonical unpadded base64url
  length of a 64-byte Ed25519 signature.
* `TAIL_CHARS = ("A", "Q", "g", "w")` — the four reachable
  last-character values.
* `TAIL_CHARS_STR = "AQgw"` — string form of ``TAIL_CHARS``.
* `ALLOWED_CHARS` — frozenset of the unpadded base64url alphabet.
* `SIG_SHAPE_VERSION = 1` — integer version of the contract.

The CLI
([`scripts/technocore_cli.py`](../scripts/technocore_cli.py))
exposes a ``sig-shape`` subcommand that reads a candidate from
``--value`` or stdin (with one trailing newline stripped) and
emits one JSON object on stdout:

```bash
$ echo "$(printf 'A%.0s' {1..85})g" | python3 scripts/technocore_cli.py sig-shape
{"ok": true, "command": "sig-shape", "result": {"valid": true, "version": 1}}
```

## Security boundary

What this validator proves:

* The candidate string is a Python ``str``.
* It has length exactly 86.
* Every character is in the unpadded base64url alphabet
  (``A-Z``, ``a-z``, ``0-9``, ``-``, ``_``).
* The last character is in ``{A, Q, g, w}``.

What this validator does **not** prove:

* That the candidate corresponds to any actual message.
* That the candidate is a valid Ed25519 signature.
* That the candidate is signed by any particular key or DID.
* That the candidate has not been tampered with.

The character shape is the same for any 64-byte buffer a caller
might construct; the surface rule is a sanity check, not an
authenticity check. Use
[`technocore_verify`](../src/technocore_verify.py) for the
cryptographic verdict.

## Why the tail is exactly four characters

An Ed25519 signature is **64** raw bytes. Encoded as unpadded
base64url:

* ``64 * 8 = 512`` bits.
* ``512 / 6 = 85.33…`` base64url characters.
* Rounded up without padding: ``86`` characters.

The trailing 1 raw byte contributes only **2** bits to the
final 6-bit group. The remaining 4 bits of that group are
always zero, so the low 4 bits of the 6-bit value are zero.
The 6-bit values whose low 4 bits are zero are
``0``, ``16``, ``32``, and ``48``. Their corresponding
base64url characters are:

| 6-bit value | Character |
|-------------|-----------|
| 0           | ``A``     |
| 16          | ``Q``     |
| 32          | ``g``     |
| 48          | ``w``     |

Hence the canonical tail is exactly ``{A, Q, g, w}`` and
nothing else.

## Edge cases

### 87-character strings

A 65-byte buffer encodes to **88** unpadded base64url
characters. A parser that *truncates* an 88-char string to
87 characters — for example by stripping one trailing ``=``
character from the padded form — can produce a string whose
tail character is in ``{A, Q, g, w}`` for some inputs, because
the same low-4-bits-zero invariant holds for the trailing
byte of a 65-byte buffer. This module rejects 87-character
strings on length **before** the tail check, so a caller that
needs to distinguish a 64-byte signature from a 65-byte tail
can rely on the length check.

The ordering — length before tail — is locked down by the
test ``test_length_check_runs_before_tail_check`` in
[`tests/test_sig_shape.py`](../tests/test_sig_shape.py).

### Padding

The standard base64 padding character ``=`` is forbidden. The
canonical encoding is unpadded. A signature that is
*base64url-encoded with padding* has length **88** and would
fail the length check; a signature that *includes a stray
``=`` in the middle* has an ``=`` character that fails the
alphabet check.

### Standard base64

The standard base64 alphabet uses ``+`` and ``/`` for the
last two values; the URL-safe variant uses ``-`` and ``_``.
A signature that was *base64-encoded* (not base64url-encoded)
has a 64-byte payload with ``+`` and ``/`` characters that
fail the alphabet check.

### Non-ASCII characters

The validator only accepts ASCII characters in the
unpadded base64url alphabet. Any non-ASCII character
(CJK, emoji, combining marks, etc.) is rejected by the
alphabet check.

## Acceptance tests

The acceptance tests live in
[`tests/test_sig_shape.py`](../tests/test_sig_shape.py)
(unit tests) and
[`tests/test_cli.py`](../tests/test_cli.py)
(``SigShapeCommandTests``, subprocess tests for the CLI
subcommand). Together they cover:

* The four reachable tail characters all pass.
* All 22 non-tail uppercase letters are rejected.
* All 24 non-tail lowercase letters are rejected.
* All 10 digit characters are rejected.
* ``-`` and ``_`` are rejected as tail characters.
* ``+``, ``/``, and ``=`` are rejected anywhere in the string.
* Lengths 0, 85, 86, 87, and 10,000 are tested.
* Every input type in the matrix (``None``, ``bytes``,
  ``int``, ``float``, ``bool``, ``list``, ``dict``, custom
  object) is rejected.
* The no-amplification contract: the validator never echoes
  the input value in the ``reason`` field.
* A real Ed25519 signature generated by the project's
  cryptographic module passes the surface check.
* A CLI subcommand round-trip: a 50-call loop produces
  identical results each time.
* The 87-char / reachable-tail edge case is rejected on
  length before the tail check.

The full test suite is run with:

```bash
python3 -m unittest discover tests -v
```

## Out of scope

* **Cryptographic verification.** The validator only checks
  the surface form. Use
  [`technocore_verify`](../src/technocore_verify.py) for
  the cryptographic verdict.
* **Verification state across rooms or DIDs.** The
  validator is stateless; replay protection across rooms
  is handled by
  [`technocore_nonce`](../src/technocore_nonce.py).
* **Did the signature come from a known peer?** Bind the
  result against an expected DID or public key in the
  cryptographic verifier, not here.
* **Signing or transport.** The validator does not sign,
  POST, fetch, decode, or follow the input.

## Versioning

The contract is pinned by the integer
[`SIG_SHAPE_VERSION`](../src/technocore_sig_shape.py). The
value is bumped whenever the public behavior of
``is_canonical_signature_shape`` or
``validate_signature_shape`` changes in a way that callers can
observe (different length, different tail set, different
error types). The current value is ``1``.

Callers should pin against the test suite, not the version
integer. The version is informational and is exposed only so
that CLI consumers and third-party implementations can detect
that they are reading the same contract.

## Limitations

* The validator only checks the *surface* canonical form of a
  candidate signature. It is not a substitute for the
  cryptographic check.
* The four reachable tail characters are a property of the
  unpadded base64url encoding of a 64-byte buffer. Any
  platform that uses a different raw length or a different
  alphabet will have a different tail set.
* The 87-character edge case is handled on length, not on
  tail. A caller that needs to accept 65-byte tails (i.e. a
  different raw length) must relax the length check
  independently.
