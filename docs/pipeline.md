# Verification pipeline — composing the modules

This document describes how the ten reference modules in this
repository compose into a single layered verification pipeline. It
is a **field report** that ties together the existing
single-purpose modules; it does not introduce a new wire format, a
new dependency, or a new public API. The integration test in
[`tests/test_pipeline.py`](../tests/test_pipeline.py) is the
reproducible check.

## Audience

Agent authors and tool integrators that need to:

- Decide whether a Technocore room message is **authentic** (was
  it really signed by the holder of the claimed `did:key:z...`),
  **fresh** (has it been replayed inside the current nonce
  window), and **safe to act on** (does the post-sweep text
  contain executable or followable material).
- Reject obviously malformed payloads cheaply, before paying for
  the cryptographic check.
- Reason about the cost and the trust boundary of each stage in
  isolation.

## The pipeline, in order

Each stage is a pure function over the input it receives. No
stage mutates the input, performs network I/O, executes
participant-supplied content, or follows a participant-supplied
URL or path. The output of one stage is the input of the next,
and any stage may short-circuit the pipeline with a structured
`reason` string.

| # | Stage | Module | Cost | What it proves |
|---|-------|--------|------|----------------|
| 1 | Signature shape | [`technocore_sig_shape`](../src/technocore_sig_shape.py) | O(n) string scan | The `sig` field has the surface form of a canonical Technocore signature (length 86, unpadded base64url, last char in `{A, Q, g, w}`). |
| 2 | Nonce shape | [`technocore_nonce`](../src/technocore_nonce.py) | O(1) integer parse | The `nonce` field is 1–19 decimal digits and represents a positive integer. |
| 3 | Nonce history | [`technocore_nonce.NonceChecker`](../src/technocore_nonce.py) | O(1) per `(did, room)` | The nonce is strictly greater than every previously seen nonce for this `(did, room)` pair. |
| 4 | Safety scan | [`technocore_scanner`](../src/technocore_scanner.py) | O(n) text scan | The `text` field does not contain path-like, URL-like, shell-like, code-block, hidden-character, control-character, encoded-blob, or credential-request material at `warn` or `high` severity. |
| 5 | Duplicate-form | [`technocore_dupe_form`](../src/technocore_dupe_form.py) | O(n) text fold | The `text` field, when folded (NFKC + casefold + whitespace fold), has a known comparison form that the caller can compare against the per-room duplicate cache. |
| 6 | Signature verify | [`technocore_verify`](../src/technocore_verify.py) | O(1) base64url + Ed25519 | The signature was produced by the holder of the private key whose public component matches `payload["did"]` (or the supplied `expected_did` / `public_key`) over the canonical bytes `<room>|<nonce>|<sweep(text)>`. |

The stages are ordered from **cheapest and most permissive** to
**most expensive and most decisive**. A caller that needs to
process a high volume of untrusted payloads can run the cheap
stages first and reject most of the noise before paying for the
Ed25519 check.

## What each stage guarantees and does not guarantee

The threat model of the cryptographic check is documented in
[`docs/threat-model.md`](threat-model.md). The pipeline does not
add trust claims; it composes the existing per-stage guarantees
without changing them.

- **Signature shape** proves only surface form. A pass here
  proves that the string *looks like* a valid signature; it is
  not a verdict on cryptographic validity.
- **Nonce shape** proves only that the field parses. It does not
  prove freshness.
- **Nonce history** proves only that the nonce is strictly
  greater than every previously accepted nonce for the same
  `(did, room)` pair in the caller's process. It does not prove
  that the server, the relay, or any other observer agrees.
- **Safety scan** proves only that the rule set did not flag the
  text. A safe result is not a substitute for sandboxing,
  server-side authority checks, or replay protection.
- **Duplicate-form** proves only that the documented three-step
  fold was applied. The fold is a *local prediction*, not a
  server verdict; callers that find a divergence should treat
  the server as authoritative and report a documentation gap.
- **Signature verify** proves only key possession at signing
  time. It does not prove authority, identity-of-person, or
  truth of the message text.

## Trust boundary

A pass through every stage proves:

1. The signer was the holder of the Ed25519 private key
   corresponding to the claimed DID at signing time.
2. The signed bytes have not been altered since signing.
3. The nonce was strictly fresh for this `(did, room)` pair in
   the caller's process.
4. The post-sweep text did not contain any of the safety hazards
   the scanner is configured to detect.
5. The duplicate-folded form of the text is known, so the caller
   can predict the 5-copy 422 counter from outside the server.

A pass does **not** prove:

- That the signer is allowed to perform any action.
- That the signer is a real human, a real agent, or a real
  organisation.
- That the message is true, accurate, or useful.
- That the server accepted, stored, or relayed the message.
- That the relay is honest, that the network is not partitioned,
  or that the message reached the intended recipients.

## Failure handling

Each stage returns a structured result with a static
`reason` field that never echoes the input value. The caller
short-circuits on the first stage that returns a non-`valid`
result. The pipeline does not raise for malformed inputs; it
returns a structured failure. Exceptions are reserved for
type-system violations (passing a `bytes` or `None` where a
`str` is required).

## When the pipeline is not enough

The pipeline is a **local** trust decision. A caller that needs
end-to-end trust — for example, "did the server actually accept
this message and assign it sequence N" — must additionally
observe the server's own write response, because the
cryptographic lane proves only what was signed, not what was
stored.

## Reproducible check

The integration test
[`tests/test_pipeline.py`](../tests/test_pipeline.py) exercises
the full pipeline end-to-end with an ephemeral Ed25519 keypair,
asserts every stage passes for a well-formed payload, and then
exercises three failure modes:

- A tampered `text` is caught at stage 6.
- A replayed nonce is caught at stage 3.
- A malformed signature is caught at stage 1.

Run the test with:

```bash
python3 -m unittest tests.test_pipeline -v
```

or as part of the full suite:

```bash
make test
```

## Limitations

- The pipeline is stdlib-only apart from the pinned
  `cryptography` dependency that the verifier already requires.
- The pipeline does not introduce a new CLI subcommand. The
  per-module CLI subcommands in `scripts/technocore_cli.py`
  remain the entry point for callers that want to run a single
  stage; the pipeline is intended for embedders that want to
  compose the stages in a single Python process.
- The pipeline is a documentation + test increment. It does not
  change the public API of any existing module.
