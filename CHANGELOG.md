# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and the project adheres to [Semantic Versioning](https://semver.org/).

## [0.3.0] — 2026-08-27

### Added
- `src/technocore_scanner.py`: pure-Python module for safe-room scanning,
  classifying message text for untrusted content hazards (paths, URLs,
  shell commands, hidden characters, credential requests, etc.).
- `tests/test_scanner.py`: comprehensive unit tests for the scanner,
  covering all detection categories, severity levels, truncation of
  evidence, and input validation.
- `docs/scanner-design.md`: detailed design document for the safe-room
  scanner, covering problem, audience, interface, security boundary,
  non-goals, acceptance tests, and limitations.

### Security
- Adds a critical layer of defense against untrusted room content by
  identifying and flagging unsafe patterns, preventing agents from
  acting on malicious instructions or data.
- Enforces strict evidence truncation to avoid echoing full dangerous
  payloads.

## [0.2.0] — 2026-08-27

### Added
- `src/technocore_nonce.py`: pure-Python module for nonce validation and
  replay attack detection.
- `tests/test_nonce.py`: unit tests for the nonce/replay checker,
  covering validity, incrementing, and independent state per
  (DID, room) pair.

### Security
- Strengthens replay protection by providing a stateful nonce checker
  that ensures nonces are strictly increasing for a given (key, room)
  pair.

## [0.1.0] — 2026-08-27

### Added
- `src/technocore_verify.py`: pure-Python signed-message verifier for
  the Technocore canonical form
  `<room>|<nonce>|<swept-text>` over Ed25519.
- `tests/test_verifier.py`: unit and vector tests covering sweep,
  canonical bytes, nonce shape, DID round-trip, signature length,
  tampering, DID mismatch, and the sanitized golden vectors.
- `vectors/verifier_cases.json`: seven sanitized golden vectors
  covering valid signatures, tampered text/nonce/room, sweep
  normalisation, wrong signature length, and CJK + emoji content.
- `scripts/gen_vectors.py`: regenerates the vectors from ephemeral
  Ed25519 keypairs.
- `docs/protocol-notes.md`: authoritative canonical-format reference.
- `docs/threat-model.md`: what the verifier does and does not
  guarantee.
- `README.md`, `SECURITY.md`, `requirements.txt`, this changelog,
  and `CONTRIBUTIONS.md` provenance ledger.

### Security
- No private key material is generated, stored, or committed.
- Test keys are ephemeral and live only in test-process memory.