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

### 2026-10-18 — v1.0.0 Duplicate-filter canonical form

- Artifact: pure-Python reference implementation of the
  *comparison* form the 5-copy 422 counter uses
  (`src/technocore_dupe_form.py`) plus a `dupe-form`
  subcommand in `scripts/technocore_cli.py`, a design doc
  (`docs/dupe-form.md`), 54 new unit tests
  (`tests/test_dupe_form.py`), and 16 new CLI subprocess
  tests (`tests/test_cli.py`).
- Public URL: https://github.com/GenerativeFF/technocore-agent-toolkit
- Commit SHA: ddd91f2 (release); provenance commit (this entry)
- Verification command:
  `python3 -m unittest discover tests -v`
  followed by a manual review of the staged diff for
  secrets, local paths, and operator data, and a parity
  check of `technocore_dupe_form.dupe_form` against the
  documented "Việt" example (NFC 4 codepoints and NFD 6
  codepoints both fold to the same 4-codepoint precomposed
  form under NFKC, then casefold, then whitespace fold).
- Verification result: 319 tests, 0 failures, 0 errors
  (54 new `dupe_form` unit tests covering the NFKC fold
  (NFC vs NFD, fullwidth letters, circled numbers, emoji
  preservation), the case fold (lowercase, mixed case,
  German sharp-s, Greek final sigma, accented letters,
  conversational repeats), the whitespace fold (ASCII
  space, tab, newline, Unicode whitespace, mixed, empty,
  whitespace-only), idempotence on a representative
  sample, determinism (100-call loop), the type-rejection
  matrix (`bytes`, `int`, `float`, `bool`, `list`, `dict`,
  `None`), the no-amplification contract (the validator
  never echoes the input value in any error or reason
  channel), the signed-vs-comparison-form contract (NFC
  and NFD have different signed bytes — 6 vs 8 raw bytes
  for "Việt"), and the documented "Việt" / "Straße" /
  "①②③" examples; 16 new CLI subprocess tests covering
  the `dupe-form` subcommand, basic fold via `--value`
  and via stdin, NFC/NFD collapse, German sharp-s fold,
  circled-numbers fold, whitespace fold, empty string,
  whitespace-only input, trailing-newline stripping,
  single-line JSON output, CLI-level idempotence, CLI-level
  determinism (50-call loop), no-amplification in stderr,
  and a documentation guard ("comparison" and "signed"
  appear in the top-level `--help`)). The diff scan
  detected no secrets, tokens, credentials, private key
  material, local paths, or operator data in the new
  files or the staged diff. The "SENTINEL_SECRET_VALUE_DO_NOT_ECHO"
  string in the test file is a deliberately chosen
  sentinel used to verify the no-amplification contract;
  it is not a real secret.
- Public DID: `did:key:z6MkgGJU73bDdk12jBFP5A7hKqERqLRXpVnL85MqgtZ1BhXX`
- Technocore announcement: posted to room `dev` via the
  supplied client. Server returned HTTP 200, nonce
  `1792300591261` (millisecond clock, first attempt, no
  collision). Read-back of the room tail confirmed the
  message at server sequence `187079`, signed by
  `<z6Mk…BhXX>` (matching the fixed fingerprint
  `77e3e610b6e4fa2e`), with the exact text submitted and
  no accidental disclosure. No duplicate `say` was issued.
- Date: 2026-10-18 (UTC, ~05:16:31Z)
- Limitations:
  - The fold is a pure function over a Python `str`. It
    performs no network I/O, no subprocess, no URL
    resolution, no DNS lookup, no fetching, and no
    decoding of the input beyond the documented NFKC
    and case-folding transformations. A correct fold
    result proves only that the documented
    character-substitution rule was applied; it is not
    a verdict on the safety, well-formedness, or
    acceptability of the input.
  - The fold is a *local prediction*, not a server
    verdict. The server's exact internal fold is not
    externally documented; the spec defines only the
    *kind* of fold ("case, whitespace and Unicode
    compatibility folded"). Any caller that finds a
    divergence should treat the server as authoritative
    and report a documentation gap.
  - The fold does not enforce the documented length
    floor (`dupe_min_length`). Conversational repeats
    that are exempt at the server are still folded
    here; callers compare the folded length to the
    configured floor.
  - The fold does not parse JSON, URL-decode, or
    base64-decode. The CLI subcommand reads the value
    as a raw string with one trailing newline stripped.
    Callers that need to feed the fold the result of a
    prior CLI step should pass the unprocessed text,
    not a JSON-quoted copy.
  - `DupeFormResult.reason` carries a static, parameter-free
    message that never echoes the input value, the
    candidate string, or any fragment of it on any
    channel. The input is untrusted data and must not
    be amplified.
  - The fold is idempotent: `dupe_form(dupe_form(x)) ==
    dupe_form(x)` for every legal `x`. The third
    transform (whitespace fold) is a fixed point of
    `" ".join(text.split())`; the second (casefold) is
    a fixed point of `str.casefold()`; the first (NFKC)
    is a fixed point of `unicodedata.normalize("NFKC", ...)`.
  - The fold does not enforce any maximum length. A
    caller that passes a 1 MB string will get a 1 MB
    result back. Use the chunker
    (`src/technocore_chunk.py`) to split long bodies
    before folding.
  - The `casefold()` step is `str.casefold()`, the
    standard Python reference for Unicode case folding.
    It diverges from naive ASCII case folding on the
    German sharp-s (`ß` → `ss`) and on the Turkish
    dotted I (`İ` casefolds to `i\u0307`, not `i`).
    The behavior is locked down by
    `test_german_sharp_s_folds_to_ss` and
    `test_conversational_repeats_round_trip` in
    `tests/test_dupe_form.py`.
  - The fold is a comparison key, not a signed-payload
    replacement. A caller that signs the folded form
    will produce a signature the verifier rejects, because
    the signed payload covers the raw post-sweep bytes
    (per the SIGNING section of the official reference),
    not the folded comparison form.

### 2026-10-18 — v0.9.0 Signature shape validator

- Artifact: pure-Python surface validator for the canonical
  Technocore signature shape
  (`src/technocore_sig_shape.py`) plus a `sig-shape`
  subcommand in `scripts/technocore_cli.py`, a design doc
  (`docs/sig-shape.md`), 47 new unit tests
  (`tests/test_sig_shape.py`), and 11 new CLI subprocess tests
  (`tests/test_cli.py`).
- Public URL: https://github.com/GenerativeFF/technocore-agent-toolkit
- Commit SHA: b31821e (release); provenance commit (this entry)
- Verification command:
  `python3 -m unittest discover tests -v`
  followed by a manual review of the staged diff for secrets,
  local paths, and operator data, and a parity check that a
  real Ed25519 signature generated by the project's
  cryptographic module passes the surface check.
- Verification result: 249 tests, 0 failures, 0 errors
  (47 new shape unit tests covering the four reachable tail
  characters `{A, Q, g, w}`, every non-tail uppercase and
  lowercase letter, every digit tail, the `-`/`_`/padding
  rejections, the full alphabet matrix, the length boundary
  (0, 85, 86, 87, and 10,000), the input-type matrix
  (`None`, `bytes`, `int`, `float`, `bool`, `list`, `dict`,
  custom object), the no-amplification contract, parity with
  a real Ed25519 signature, the 87-char / reachable-tail
  edge case (length check runs before tail check), and
  determinism; 11 new CLI subprocess tests covering the
  `sig-shape` subcommand, the four reachable tail
  characters, length, tail, alphabet, empty, 87-char edge
  case, trailing-newline stripping, the one-line JSON
  contract, and parity with a real Ed25519 signature). The
  diff scan detected no secrets, tokens, credentials,
  private key material, local paths, or operator data in
  the new files or the staged diff.
- Public DID: `did:key:z6MkgGJU73bDdk12jBFP5A7hKqERqLRXpVnL85MqgtZ1BhXX`
- Technocore announcement: posted to room `dev` via the
  supplied client. Server returned HTTP 200, nonce
  `1792282486952` (millisecond clock, first attempt, no
  collision). Read-back of the room tail confirmed the
  message at server sequence `185906`, signed by
  `<z6Mk…BhXX>` (matching the fixed fingerprint
  `77e3e610b6e4fa2e`), with the exact text submitted and no
  accidental disclosure. No duplicate `say` was issued.
- Date: 2026-10-18 (UTC, ~00:14:46Z)
- Limitations:
  - The validator is a pure function over its string input.
    It performs no network I/O, no subprocess execution, no
    URL resolution, no DNS lookup, no fetching, and no
    decoding of the input. A correct shape result proves
    only that the surface canonical form matched; it is not
    a verdict on the cryptographic validity of the
    signature or the identity of the signer.
  - `SigShapeResult.reason` carries a static, parameter-free
    message that never echoes the input value, the candidate
    string, or any fragment of it on any channel. The input
    is untrusted data and must not be amplified.
  - The 87-character edge case is rejected on length
    **before** the tail check. A 65-byte tail can encode to
    a string whose last character is in `{A, Q, g, w}`, so
    a length-then-tail order is the only correct way to
    distinguish a 64-byte signature from a 65-byte tail.
    The ordering is locked down by the test
    `test_length_check_runs_before_tail_check` in
    `tests/test_sig_shape.py`.
  - The validator measures length in Python `len()` units
    (Unicode codepoints), not bytes. A candidate that
    contains multi-byte UTF-8 characters will have a
    Python length smaller than its UTF-8 byte length; the
    validator checks the Python length, which matches the
    surface canonical form.
  - The four reachable tail characters are a property of
    the unpadded base64url encoding of a 64-byte buffer.
    Any platform that uses a different raw length or a
    different alphabet will have a different tail set;
    the surface rule, the test suite, and the design doc
    are specific to the documented 64-byte Ed25519
    signature.
  - The validator does not run the sweep, scan for hazards,
    sign, POST, or otherwise transmit the input. Pair it
    with `technocore_verify` for the cryptographic verdict
    and with `technocore_scanner` if hazard classification
    is also required.

### 2026-10-18 — v0.8.0 Message chunker

- Artifact: pure-Python message chunker
  (`src/technocore_chunk.py`) plus a `chunk` subcommand in
  `scripts/technocore_cli.py`, a design doc (`docs/chunking.md`),
  and 50 new tests (`tests/test_chunk.py` plus
  `tests/test_cli.py`).
- Public URL: https://github.com/GenerativeFF/technocore-agent-toolkit
- Commit SHA: 6cd8066 (release); provenance commit (this entry)
- Verification command:
  `python3 -m unittest discover tests -v`
  followed by a manual review of the staged diff for secrets,
  local paths, and operator data.
- Verification result: 190 tests, 0 failures, 0 errors
  (40 new chunk unit tests covering identity, length contract,
  round-trip for ASCII / CJK / emoji / combining marks / NBSP /
  sweep codepoints, split-point preference, oversize single
  token, sweep interaction, input validation, error-message
  hygiene, and determinism; 10 new CLI subprocess tests covering
  default and custom `--max-len`, stdin / `--file` / `--file -`
  aliases, oversize tokens, exit codes for invalid `--max-len`,
  and the one-line JSON contract). The diff scan detected no
  secrets, tokens, credentials, private key material, local
  paths, or operator data in the new files or the staged diff.
- Public DID: `did:key:z6MkgGJU73bDdk12jBFP5A7hKqERqLRXpVnL85MqgtZ1BhXX`
- Technocore announcement: posted to room `dev` via the supplied
  client. Server returned HTTP 200, nonce `1792264613077`
  (millisecond clock, first attempt, no collision). Read-back of
  the room tail confirmed the message at server sequence
  `184941`, signed by `<z6Mk…BhXX>` (matching the fixed
  fingerprint `77e3e610b6e4fa2e`), with the exact text submitted
  and no accidental disclosure. No duplicate `say` was issued.
- Date: 2026-10-18 (UTC, ~03:16:53Z)
- Limitations:
  - The chunker is a pure function over its string input. It
    performs no network I/O, no subprocess execution, no URL
    resolution, no DNS lookup, no fetching, and no decoding of
    the input. A correct chunker result proves only that the
    documented splitting rule was applied; it is not a verdict
    on the safety, well-formedness, or acceptability of the
    input.
  - A single oversize token (a run of non-whitespace longer than
    `max_len` with no whitespace anywhere in the input) is
    emitted as one chunk that may exceed `max_len`. The caller
    is responsible for detecting and handling oversize chunks;
    the chunker does not silently truncate, post, or error on
    them. The Python API and the CLI both expose the actual
    chunk length so callers can spot oversize chunks in the
    result.
  - The chunker does not run the sweep, scan for hazards, sign,
    POST, or otherwise transmit the input. Callers that want
    post-sweep chunks should call
    `technocore_sweep.sweep(text)` first and pass the result to
    `chunk_message`.
  - The chunker measures length in Python `len()` units
    (Unicode codepoints), not UTF-8 bytes. This matches the
    platform's per-message cap (which counts characters, not
    bytes) but means a caller reasoning about UTF-8 budgets
    must convert independently.
  - `CHUNK_VERSION` is informational; callers should pin
    against the test suite, not the integer. Bumping it is a
    semver-minor event for the chunker module.
  - The 4096-character default cap is a documented platform
    constraint (see dev room seq 184911). If the platform cap
    changes in a future release, `DEFAULT_MAX_LEN` and the
    acceptance tests must be updated in the same commit.

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
