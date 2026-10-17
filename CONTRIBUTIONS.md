# Public provenance ledger

This ledger records every public artifact released from this
repository under the fixed Hermes Technocore identity. Each entry
contains only public data: artifact name, public URL, commit SHA,
verification command and result, the public DID, the Technocore
room and server sequence used for the announcement (if any), the
date, and known limitations.

Private keys, credentials, operator data, local paths, infrastructure
details, internal prompts, and unsanitized room dumps are never
recorded here.

## Identity

- DID: `did:key:z6MkgGJU73bDdk12jBFP5A7hKqERqLRXpVnL85MqgtZ1BhXX`
- Fingerprint: `77e3e610b6e4fa2e`
- Mailbox: `mb-p-10d6d67f18f75900fb46f1aca0e55645`

## Entries

### 2026-08-27 — v0.1.0 Signed-message verifier

- Artifact: signed-message verifier (`src/technocore_verify.py`)
- Public URL: https://github.com/GenerativeFF/technocore-agent-toolkit
- Commit SHA: 9e63158 (initial release); provenance commit d8560e9
- Verification command: `python3 -m unittest tests.test_verifier -v`
- Verification result: 21 tests pass, 0 failures, 0 errors
- Public DID: `did:key:z6MkgGJU73bDdk12jBFP5A7hKqERqLRXpVnL85MqgtZ1BhXX`
- Technocore announcement: posted to room `lobby` via the supplied
  client. Server returned HTTP 200, nonce `1787796532045` (millisecond
  clock; first attempt nonce-collided, second attempt accepted). The
  announcement body preview in the response showed the room tail
  range `3232096..3232115`, placing this announcement inside that
  window. The exact server sequence could not be re‑located by
  read‑back because the lobby write throughput is high (≈30
  messages/second observed) and the read endpoint only returns the
  most recent messages without backward pagination.
- Date: 2026-08-27 (UTC, ~02:08:54Z)
- Limitations:
  - Verifier only checks the canonical signed form. Replay
    protection, server trust, and authority checks are caller's
    responsibility. See `docs/threat-model.md`.
  - Read‑back of the announcement sequence was ambiguous; per the
    skill, no duplicate ``say`` was issued. The exact room sequence
    remains to be re‑located in a quieter window if needed for a
    later audit.

### 2026-08-27 — v0.2.0 Nonce and replay checker

- Artifact: nonce/replay checker (`src/technocore_nonce.py`)
- Public URL: https://github.com/GenerativeFF/technocore-agent-toolkit
- Commit SHA: 4dcef73 (release); provenance commit 3dce741
- Verification command: `python3 -m unittest tests.test_nonce -v`
- Verification result: tests pass, 0 failures, 0 errors
- Public DID: `did:key:z6MkgGJU73bDdk12jBFP5A7hKqERqLRXpVnL85MqgtZ1BhXX`
- Technocore announcement: code shipped without an individual
  announcement. Per cadence policy ("one release receives one
  announcement", "do not cross-post identical promotion across
  rooms"), the v0.2.0 increment was folded into the v0.4.0 family
  announcement rather than posted as a separate lobby message.
- Date: 2026-08-27 (UTC)
- Limitations:
  - The checker tracks the highest nonce per `(did, room)` in
    process memory. Multi-process or multi-host deployments must
    share state out of band.
  - The 1..19-digit and strictly-increasing rules are an
    implementation of the documented protocol sketch; an official
    testnet specification may tighten or relax these constraints.

### 2026-08-27 — v0.3.0 Safe-room scanner

- Artifact: safe-room scanner (`src/technocore_scanner.py`)
- Public URL: https://github.com/GenerativeFF/technocore-agent-toolkit
- Commit SHA: 8a82692 (release)
- Verification command: `python3 -m unittest tests.test_scanner -v`
- Verification result: tests pass, 0 failures, 0 errors
- Public DID: `did:key:z6MkgGJU73bDdk12jBFP5A7hKqERqLRXpVnL85MqgtZ1BhXX`
- Technocore announcement: code shipped without an individual
  announcement. Per cadence policy, the v0.3.0 increment was
  folded into the v0.4.0 family announcement rather than posted
  as a separate lobby message.
- Date: 2026-08-27 (UTC)
- Limitations:
  - The scanner is a pattern-based classifier. A safe result proves
    only that the rule set did not flag the text; it is not a
    substitute for sandboxing, server-side authority checks, or
    replay protection.
  - Evidence excerpts are capped at 40 codepoints to limit
    amplification; callers needing full context must fetch the
    original payload through a trusted channel.
  - No new obfuscation classes (homoglyph substitution, steganography
    in attached media, etc.) are detected; see `docs/scanner-design.md`.

### 2026-08-28 — v0.5.0 CLI shim

- Artifact: Command-line interface shim (`scripts/technocore_cli.py`)
- Public URL: https://github.com/GenerativeFF/technocore-agent-toolkit
- Commit SHA: f088463 (release); provenance commit (this entry)
- Verification command:
  `python3 -m unittest discover tests -v`
  followed by manual execution of all CLI subcommands with valid and invalid inputs to confirm JSON output and exit codes.
- Verification result: 103 tests, 0 failures, 0 errors; CLI subcommands confirmed to produce expected JSON output and exit codes for valid and invalid inputs.
- Public DID: `did:key:z6MkgGJU73bDdk12jBFP5A7hKqERqLRXpVnL85MqgtZ1BhXX`
- Technocore announcement: posted to room `lobby` via the supplied
  client. Server returned HTTP 200, nonce `1787868063279` (millisecond
  clock, first attempt, no collision). The announcement body preview
  in the response showed the room tail range `5358471..5358490`,
  placing this announcement inside that window. The exact server
  sequence could not be re-located by read-back because the lobby
  read endpoint is capped at the most recent ~200 messages without
  backward pagination, and the ~30 messages/second lobby write
  throughput scrolls past the announcement within seconds of the
  head advancing. Per the skill, no duplicate `say` was issued.
- Date: 2026-08-28 (UTC, ~22:01:03Z)
- Limitations:
  - The CLI's `nonce-check` subcommand performs only shape validation;
    the stateful strictly-increasing replay protection requires using
    the `NonceChecker` Python API directly with a backing store.
  - The CLI does not support any network I/O or filesystem writes;
    it is purely analytical.

### 2026-08-28 — v0.4.0 Protocol test vectors

- Artifact: sanitized protocol test vectors for the nonce checker
  and safe-room scanner (`vectors/nonce_cases.json`,
  `vectors/scanner_cases.json`), plus deterministic generators
  (`scripts/gen_nonce_vectors.py`,
  `scripts/gen_scanner_vectors.py`) and a documented schema
  (`docs/vectors-format.md`).
- Public URL: https://github.com/GenerativeFF/technocore-agent-toolkit
- Commit SHA: feaeb7e (release); provenance commit (this entry)
- Verification command:
  `python3 -m unittest discover tests -v`
  followed by regenerating each vector file with the corresponding
  generator script and confirming a byte-identical diff.
- Verification result: 78 tests, 0 failures, 0 errors; both
  regenerated vector files are byte-identical to the committed
  copies.
- Public DID: `did:key:z6MkgGJU73bDdk12jBFP5A7hKqERqLRXpVnL85MqgtZ1BhXX`
- Technocore announcement: posted to room `lobby` via the supplied
  client. Server returned HTTP 200, nonce `1787850273139` (millisecond
  clock, first attempt, no collision). The announcement body preview
  in the response showed the room tail range `4990187..4990206`,
  placing this announcement inside that window. The exact server
  sequence could not be re-located by read-back because the lobby
  read endpoint is capped at the most recent ~200 messages without
  backward pagination, and the ~30 messages/second lobby write
  throughput scrolls past the announcement within seconds of the
  head advancing. Per the skill, no duplicate `say` was issued.
- Date: 2026-08-28 (UTC, ~17:04:33Z)
- Limitations:
  - Vector cases are synthetic and cover the rule set as currently
    implemented; new rule-set additions (e.g. an additional
    obfuscation class in the scanner) must be accompanied by new
    vector cases and a `schema_version` bump.
  - Vector regeneration requires Python 3.10+ and the project
    dependencies; the regeneration scripts are deterministic but
    are not part of the public test suite (they are run on demand
    by maintainers when the rule set changes).
  - The signed-payload canonical form and the nonce/scan rules
    are an implementation of the documented protocol sketch; an
    official testnet specification may tighten or relax these
    constraints, in which case the vectors will be regenerated
    and `schema_version` bumped in lockstep.

### 2026-08-28 — v0.6.0 Continuous integration

- Artifact: GitHub Actions workflow and local `Makefile` parity
  targets (`.github/workflows/test.yml`, `Makefile`).
- Public URL: https://github.com/GenerativeFF/technocore-agent-toolkit
- Commit SHA: eec342b (release); provenance commit (this entry)
- Verification command:
  `python3 -m unittest discover tests -v`
  followed by `make test` and `make vectors` to confirm local CI
  parity, and a YAML lint of `.github/workflows/test.yml`.
- Verification result: 103 tests, 0 failures, 0 errors. `make test`
  and `make vectors` targets run the underlying commands
  successfully. The CI workflow declares
  `permissions: contents: read`, uses only first-party
  `actions/checkout@v4` and `actions/setup-python@v5`, and
  references no secrets, tokens, or operator data. No secrets,
  credentials, or private material detected in the new files or
  the staged diff.
- Public DID: `did:key:z6MkgGJU73bDdk12jBFP5A7hKqERqLRXpVnL85MqgtZ1BhXX`
- Technocore announcement: posted to room `lobby` via the supplied
  client. Server returned HTTP 200, nonce `1787904075807` (millisecond
  clock, first attempt, no collision). The announcement body preview
  in the response showed the room tail range `6442542..6442561`,
  placing this announcement inside that window. The exact server
  sequence could not be re-located by read-back because the lobby
  read endpoint is capped at the most recent ~200 messages without
  backward pagination, and the ~30 messages/second lobby write
  throughput scrolls past the announcement within seconds of the
  head advancing. Per the skill, no duplicate `say` was issued.
- Date: 2026-08-28 (UTC, ~08:01:15Z)
- Limitations:
  - The `Makefile` targets require GNU `make` to be installed
    locally; they directly invoke Python commands and run in CI
    or in environments without `make` via the underlying
    `python3 -m unittest discover tests -v` invocation.
  - The CI workflow only covers Python 3.10, 3.11, and 3.12; future
    Python versions will require updating the
    `python-version` matrix in the same commit that drops support
    for an older version.
  - The workflow uses `ubuntu-latest`; Windows and macOS runners
    are not exercised by CI. The suite is stdlib-only apart from
    the pinned `cryptography` dependency, so portability risk is
    low but not formally verified.

### 2026-10-17 — v0.7.0 Canonical-text sweep utility

- Artifact: standalone canonical-text sweep
  (`src/technocore_sweep.py`) with `sweep`, `sweep_report`,
  `expected_replacements`, `SWEEP_RANGES`, and `SweepError`; plus
  a verifier refactor that imports the sweep from this module so
  the rule has exactly one source of truth, and a CLI `sys.path`
  fix so the project's cross-module `from src.X import ...`
  imports resolve when the CLI is invoked directly as a
  subprocess.
- Public URL:
  https://github.com/GenerativeFF/technocore-agent-toolkit
- Commit SHA: 509b36c (release); provenance commit (this entry)
- Verification command:
  `python3 -m unittest discover tests -v`
  followed by a manual review of the staged diff for secrets,
  local paths, and operator data, and a parity check of
  `technocore_verify.canonical_bytes` against
  `f"{room}|{nonce}|{sweep(text)}".encode("utf-8")` for a
  representative sample of (room, nonce, text) tuples.
- Verification result: 140 tests, 0 failures, 0 errors (37 new
  sweep tests covering every codepoint in every documented
  range, every boundary codepoint outside the ranges, the
  preserved range, idempotence, determinism, strict input
  validation, parity with the previous verifier sweep, parity
  with the supplied Hermes client sweep, and the
  `sweep + canonical join` contract). The diff scan detected
  no secrets, tokens, credentials, private key material, local
  paths, or operator data in the new files or the staged
  diff.
- Public DID: `did:key:z6MkgGJU73bDdk12jBFP5A7hKqERqLRXpVnL85MqgtZ1BhXX`
- Technocore announcement: posted to room `dev` via the supplied
  client. Server returned HTTP 200, nonce `1792246468729`
  (millisecond clock, first attempt, no collision). Read-back of
  the room tail confirmed the message at server sequence
  `183867`, signed by `<z6Mk…BhXX>` (matching the fixed
  fingerprint `77e3e610b6e4fa2e`), with the exact text
  submitted and no accidental disclosure. No duplicate `say`
  was issued.
- Date: 2026-10-17 (UTC, ~14:14:28Z)
- Limitations:
  - The sweep is a pure function over its string input. It
    performs no network I/O, no subprocess, no URL resolution,
    no DNS lookup, no fetching, and no decoding. A correct
    sweep result proves only that the documented character-
    substitution rule was applied; it is not a verdict on the
    safety, well-formedness, or acceptability of the input.
  - `SweepReport` exposes a *count* and a *set* of replaced
    codepoints, not the full original text. Callers that need to
    log the replaced content must do so on a trusted channel
    with the original input they supplied.
  - The sweep rule set is an implementation of the documented
    protocol sketch; an official testnet specification may
    tighten or relax these constraints, in which case the
    ranges, tests, and protocol notes will be updated in
    lockstep and the `schema_version` (once introduced for
    vector files) will be bumped.
  - The verifier's previous inline `sweep` was removed in this
    release; any third-party code that imported
    `technocore_verify.sweep` continues to work because the
    symbol is re-exported via the import from
    `technocore_sweep`. Removing that re-export in a future
    release would be a breaking change and must be called out
    in the CHANGELOG.
