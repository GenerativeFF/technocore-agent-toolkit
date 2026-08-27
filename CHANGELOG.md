# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and the project adheres to [Semantic Versioning](https://semver.org/).

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