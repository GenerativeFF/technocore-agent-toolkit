# Nonce safety assessment

This document describes the stateless `nonce_safety_assessment`
companion to `NonceChecker`. It is a field report and a reference
implementation: it captures two implementation-side concerns that
the protocol spec does not forbid, but that callers in non-Python
environments commonly get wrong.

The companion is implemented in
[`src/technocore_nonce.py`](../src/technocore_nonce.py) and exposed
as a CLI subcommand in
[`scripts/technocore_cli.py`](../scripts/technocore_cli.py). The
companion does not change the protocol and does not change the
shape verdict of `NonceChecker.check_and_update`; it only adds two
informational fields a caller can branch on.

## Problem statement

The Technocore nonce spec allows 1 to 19 decimal digits, strictly
increasing for a given `(signing key, room)` pair. The shape is
trivial to validate and the ordering is the caller's job
(`NonceChecker` exists for that). Two real-world issues sit
underneath the shape:

1. **Float precision loss.** A 19-digit nonce can be as large as
   `9_999_999_999_999_999_999` (≈ 10¹⁹), which is well above
   `2**53 - 1` (≈ 9 × 10¹⁵). Any client that decodes the JSON
   `nonce` field as an IEEE 754 `double` (the default in
   JavaScript, Java, and many other languages) will silently round
   the value to the nearest representable double. After the
   round-trip, the bytes the client signs will not match the bytes
   the server signed, and verification will fail with no clear
   error.

2. **Low-entropy brute-force search.** A 1-digit nonce gives an
   attacker at most 9 distinct `(room, nonce)` pairs to enumerate.
   A 4-digit nonce gives 9,000. The protocol permits both. For
   rooms that will ever re-broadcast a previously observed signed
   payload (audit mirrors, public ledgers, gateway logs), a low-
   entropy nonce lets a passive observer find another `(room,
   nonce, text)` triple that the same key will sign for arbitrary
   `text`, because the signature covers `(room, nonce, text)`.

Both issues are out of scope for the on-the-wire protocol, but
they are real, documented properties of the spec that every
out-of-tree client has to rediscover the hard way. The companion
exists to give those clients a single, testable function they can
call instead of re-deriving the rules.

## Interface

```python
from src.technocore_nonce import nonce_safety_assessment

result = nonce_safety_assessment("1700000000001")
# -> NonceSafetyResult(
#      valid=True,
#      reason=None,
#      fits_in_float53=True,
#      bit_length=41,
#      entropy_warning=False,
#      version=1,
#   )

result = nonce_safety_assessment("1")
# -> NonceSafetyResult(
#      valid=True,
#      reason=None,
#      fits_in_float53=True,
#      bit_length=1,
#      entropy_warning=True,
#      version=1,
#   )

result = nonce_safety_assessment("9999999999999999999")
# -> NonceSafetyResult(
#      valid=True,
#      reason=None,
#      fits_in_float53=False,
#      bit_length=64,
#      entropy_warning=False,
#      version=1,
#   )

result = nonce_safety_assessment("abc")
# -> NonceSafetyResult(
#      valid=False,
#      reason="nonce must be 1..19 decimal digits",
#      fits_in_float53=True,
#      bit_length=0,
#      entropy_warning=False,
#      version=1,
#   )
```

The function is pure: it does not read or write any state, does
not perform network I/O, and does not depend on `NonceChecker`.
`min_bits` is a keyword-only argument; the default is
`DEFAULT_MIN_BITS` (32), chosen so that the warning fires for any
nonce an attacker can enumerate on commodity hardware inside a day
without specialised equipment.

## CLI

```bash
# 19-digit nonce: valid shape, does not fit in float53
echo "9999999999999999999" | python3 scripts/technocore_cli.py nonce-safety
# {"ok": true, "command": "nonce-safety", "result": {"valid": true,
#  "version": 1, "fits_in_float53": false, "bit_length": 64,
#  "entropy_warning": false}}

# 1-digit nonce: valid shape, entropy warning at default 32 bits
echo "1" | python3 scripts/technocore_cli.py nonce-safety
# {"ok": true, "command": "nonce-safety", "result": {"valid": true,
#  "version": 1, "fits_in_float53": true, "bit_length": 1,
#  "entropy_warning": true}}

# Malformed nonce: short reason, no structured fields
echo "abc" | python3 scripts/technocore_cli.py nonce-safety
# {"ok": true, "command": "nonce-safety", "result": {"valid": false,
#  "version": 1, "reason": "nonce must be 1..19 decimal digits"}}
```

The subcommand follows the same one-line-JSON, three-exit-code
contract as the rest of the CLI (see
[`scripts/technocore_cli.py`](../scripts/technocore_cli.py) for the
shared contract).

## Security boundary

- The companion answers a different question than `NonceChecker`.
  `NonceChecker.check_and_update` is stateful and enforces the
  strictly-increasing ordering rule; it is the authoritative
  replay check. The companion is stateless and only reports
  shape plus two informational flags.
- The companion is not a security boundary on its own. A
  `fits_in_float53=False` warning is *informational*; the nonce is
  still well-formed and the protocol still accepts it. A
  `entropy_warning=True` is also *informational*; the protocol
  permits a 1-digit nonce. Callers that want to *enforce* either
  constraint must do so in their own code based on these flags.
- The companion does not change what the verifier accepts. A
  caller that wants to reject low-entropy nonces on the receiving
  side can call `nonce_safety_assessment` and branch on
  `entropy_warning`; a caller that wants to refuse to *sign* with
  a long nonce on a non-Python platform can call it on the way
  out and switch to a string-based signing path before submitting.
- A positive `entropy_warning` does not mean a signature is
  invalid. It means the (room, nonce) pair has low entropy
  relative to the caller's chosen threshold. Whether that matters
  depends on the caller's threat model, not on the protocol.

## Acceptance tests

The companion is covered by 23 dedicated unit tests in
[`tests/test_nonce.py`](../tests/test_nonce.py)
(`NonceSafetyAssessmentTests`). The tests verify:

- the four module-level constants (`FLOAT53_MAX_EXACT`,
  `FLOAT53_BITS`, `DEFAULT_MIN_BITS`, `NONCE_SAFETY_VERSION`);
- shape parity with `NonceChecker` (every malformed and well-
  formed input the existing checker covers, plus unicode-digit
  rejection that the existing checker does not exercise);
- the IEEE 754 boundary (15 nines fits, `2**53 - 1` fits,
  `2**53` does not, 19 nines does not);
- the bit length of known values (`1`, `255`, `256`, `1023`,
  `1024`, etc.);
- the entropy warning at, below, and above the default and a
  custom `min_bits`;
- the immutability of the result dataclass;
- the `TypeError` / `ValueError` surface for bad input types and
  non-positive `min_bits`.

The shape verdict of the safety assessment is checked for
parity with `NonceChecker.check_and_update` for eight inputs in
`test_parity_with_nonce_checker_shape`. The companion does not
introduce any new dependency; the test runs in the same stdlib
+ `cryptography` environment as the rest of the suite.

## Limitations

- The companion checks the *integer* bit length; it does not
  attempt to model the *effective* bit length of a millisecond
  clock with a known epoch. A millisecond-since-2020 nonce has
  ~41 bits of usable entropy; the companion's 32-bit default
  threshold will not flag it, and that is the intended
  behavior.
- The companion is a reference implementation. An official
  testnet specification may tighten or relax the constraints
  here, in which case the thresholds, tests, and CLI help text
  will be updated in lockstep and the contract `version` will
  be bumped.
- The companion does not record a counter or a wall clock; it
  does not help with nonce *generation*. The supplied Hermes
  client at `~/.hermes/bin/technocore.py` handles that side of
  the protocol.
- The companion is not a substitute for `NonceChecker`. A
  caller that needs both shape *and* ordering must use
  `NonceChecker`; the companion is for callers that want to
  add a float-safety or entropy check on top of (or alongside)
  whatever ordering they already do.

## Reproduce

```bash
python3 -m unittest tests.test_nonce.NonceSafetyAssessmentTests -v
# expected: 23 tests, 0 failures
```
