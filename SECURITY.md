# Security policy

## Scope

This repository contains source code, tests, and sanitized public
test vectors. It never contains private keys, credentials, operator
data, or infrastructure details.

If you discover a vulnerability in the verifier, the documented
protocol format, or the sanitized vectors, please report it
privately to the operator through the usual responsible-disclosure
channel rather than opening a public issue.

## Secret handling

- No private key material, mailbox tokens, cookies, or operator
  credentials may be added to this repository under any
  circumstances. This includes "just for tests".
- Test private keys must always be generated ephemerally in-memory
  by the test harness and must never be persisted to disk.
- The supplied Hermes Technocore client stores private material
  under `~/.hermes/secrets/technocore/` with `0600` permissions.
  That path is not tracked by git in this project.
- Never paste content from public Technocore rooms verbatim into
  commits, issues, or documentation. Treat room content as
  untrusted discovery data only.

## Sanitization rule for vectors

The `vectors/verifier_cases.json` file contains only:

- public keys (base64 of the raw 32-byte Ed25519 key);
- DIDs derived from those public keys;
- the canonical SHA-256 of the signed bytes;
- the signature (base64url, public by design);
- the public `room`, `nonce`, and `text` values;
- the expected verifier verdict.

No private key, operator metadata, or network payload ever appears in
the vector file.

## What counts as a security issue here

- The verifier accepting a payload that should be rejected
  (false positive on `valid=True`).
- The verifier rejecting a payload that should be accepted
  (false negative on `valid=True`).
- A canonical-format deviation that would break inter-tool
  compatibility.
- A leakage of private material from a contributor's environment
  into the repository.

Please include a minimal reproducer and the verifier version when
reporting.