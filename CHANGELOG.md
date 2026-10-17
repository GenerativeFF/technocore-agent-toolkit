# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and the project adheres to [Semantic Versioning](https://semver.org/).

## [0.7.0] — 2026-10-17

### Added
- `src/technocore_sweep.py`: public, reference implementation of the
  protocol's single-pass control-character sweep. Pure Python,
  stdlib-only, no network I/O, no subprocess, no decoding. Exposes:
  - `sweep(text)` — returns the post-sweep string.
  - `sweep_report(text)` — returns a `SweepReport` with the post-sweep
    string, the count of replaced codepoints, and the distinct
    set of replaced codepoints.
  - `expected_replacements(text)` — returns `(count, distinct_set)`
    without allocating the swept string.
  - `SWEEP_RANGES` — the four documented inclusive-lower,
    exclusive-upper codepoint ranges.
  - `SweepError` — raised for non-string input.
- `tests/test_sweep.py`: 37 unit tests covering the four documented
  ranges, boundary codepoints (first in, one past the upper bound),
  preserved ranges (U+0020, U+00A0, U+2010, U+202F, CJK, emoji,
  combining marks, Latin ligatures), length preservation, idempotence
  (`sweep(sweep(x)) == sweep(x)`), determinism, strict input
  validation, parity with `technocore_verify.sweep` and with the
  supplied Hermes client sweep, and the `sweep + canonical join`
  contract against `technocore_verify.canonical_bytes`.

### Changed
- `src/technocore_verify.py`: now imports the sweep from
  `technocore_sweep` so the verifier and any third-party signer share
  exactly one rule. The verifier's behaviour is byte-for-byte
  unchanged; the full unit and vector test suites still pass.
- `scripts/technocore_cli.py`: the in-script `sys.path` setup now
  adds both the repository root and `src/` to the path so the
  project's cross-module `from src.X import ...` imports resolve
  when the CLI is invoked directly as a subprocess.
- `docs/protocol-notes.md`: the "Sweep rules" section now points at
  `src/technocore_sweep.py` as the single source of truth and
  cross-references the `tests/test_sweep.py` range coverage.
- `README.md`: status block, table of contents, and "Quickstart"
  updated to reference the sweep module.

### Security
- The sweep module is a pure function over its string input. It
  performs no network I/O, no filesystem I/O beyond the input
  string, no subprocess execution, no URL resolution, no DNS lookup,
  no fetching, and no decoding of the input.
- `SweepReport` exposes a *count* and a *set* of replaced
  codepoints, not the full original text. Callers that need to log
  the replaced content must do so on a trusted channel with the
  original input they supplied.

## [0.6.0] — 2026-08-28

### Added
- **Continuous integration**: `.github/workflows/test.yml` runs the
  full unit-test suite on every push to `main` and on every pull
  request. The matrix covers Python 3.10, 3.11, and 3.12 on
  `ubuntu-latest`. The workflow only installs the single pinned
  dependency (`cryptography>=42.0.0`) from PyPI and runs the stdlib
  `unittest` discovery; it uses no third-party GitHub Actions, no
  secrets, and no additional network calls.
- **Local parity targets**: a top-level `Makefile` exposes `make
  test`, `make vectors`, `make all`, `make check`, and `make clean`
  so contributors can reproduce CI locally before opening a PR.
- **README**: added the tests-workflow status badge at the top of
  the file, expanded the "Reproduce the test suite" section to
  include the `make test` shortcut, and added a dedicated
  "Continuous integration (v0.6.0)" section documenting the Python
  version matrix.

### Security
- The workflow uses `permissions: contents: read` so a compromised
  dependency cannot escalate to write tokens on the repository.
- No secrets, tokens, fingerprints, or private key material are
  referenced by the workflow. If you ever add one, do so via
  repository `Settings → Secrets and variables → Actions` and
  reference the GitHub-provided `${{ secrets.* }}` form; never
  inline a secret.
- `make clean` only removes Python bytecode caches
  (`__pycache__/` and `*.pyc`) and does not touch tracked files.

## [0.5.0] — 2026-08-28

### Added
- `scripts/technocore_cli.py`: stdlib-only command-line shim exposing
  all three building blocks as subcommands:
  - `scan` — classify text from stdin or `--file` for untrusted-
    content hazards (paths, URLs, shell metacharacters, imperative
    verbs, fenced/indented code blocks, hidden and control
    characters, encoded blobs, credential requests).
  - `verify` — verify a signed-message payload JSON from `--payload`
    or stdin against an optional `--public-key` (32-byte hex) and
    optional `--expected-did`.
  - `nonce-check` — validate the shape of a `(did, room, nonce)`
    triple. The strictly-increasing replay check is intentionally
    process-local; use the `NonceChecker` Python API for stateful
    deployments.
- `tests/test_cli.py`: 25 subprocess tests covering argument parsing,
  exit codes, one-line JSON output, stdin / file / dash-alias I/O,
  valid and tampered payloads, key-length and hex validation, and
  malformed JSON.
- `README.md`: documented the CLI usage, exit-code semantics, and
  the role of the `nonce-check` shape-only validation.

### Security
- The CLI performs no network I/O, no subprocess execution, no
  filesystem writes, and no decoding of base64/hex/blob payloads.
  All inputs are treated as untrusted data and never executed,
  fetched, or followed.
- Errors are emitted as a one-line JSON object on stderr; no secret
  material, internal paths, or environment data are echoed.

## [0.4.0] — 2026-08-28

### Added
- **Protocol Test Vectors**: Added deterministic test vectors for the nonce checker and safe-room scanner modules:
  - `vectors/nonce_cases.json`: Covers valid nonces, replay attacks, and various invalid formats.
  - `vectors/scanner_cases.json`: Covers detection of paths, URLs, shell commands, instructions, code blocks, hidden characters, control characters, encoded blobs, and credential requests.
- **Vector Generation Scripts**: Added Python scripts to generate these vectors deterministically:
  - `scripts/gen_nonce_vectors.py`
  - `scripts/gen_scanner_vectors.py`
- **Documentation**: Added `docs/vectors-format.md` detailing the schema for test vector files.
- **README and Changelog Updates**: Updated to reflect the new v0.4.0 milestone, including installation and regeneration instructions for the new vector types.

### Changed
- Updated ``README.md`` to include installation and regeneration instructions for the new vector types and added v0.4.0 to the status section.
- Updated ``CHANGELOG.md`` to document the changes for v0.4.0.

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
