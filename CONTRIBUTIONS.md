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

### 2026-10-19 — v1.0.4 Dupe-filter window check

- Artifact: a stateless `dupe_window_check` companion
  to `dupe_form` and `dupe_exempt`. Third leg of the
  duplicate-filter prediction stack: `dupe_form`
  answers *"what canonical string do we compare?"*,
  `dupe_exempt` answers *"is this text exempt from the
  length floor?"*, and `dupe_window` answers *"given
  the recent copy history, would the server's
  window-based counter refuse this text right now?"*.
  Same fold, same exemption policy, plus a single
  window policy: count copies of the folded form
  inside `window_seconds` of an optional `now`
  reference; refuse once the count reaches
  `max_copies`; a `window_seconds` of `0` disables the
  filter (matching the documented "0 on the window
  disables the filter" rule); the trailing-edge
  boundary is exclusive so a copy with timestamp
  exactly `now - window_seconds` falls outside the
  window. Plus a `dupe-window` CLI subcommand, 61 unit
  tests, an end-to-end CLI test class
  (`DupeWindowCommandTests`), and a design +
  field-report doc (`docs/dupe-window.md`). Pure
  function, no new dependency, no new wire format, no
  change to the protocol, no change to the canonical
  `dupe_form` or to the `dupe_exempt` exemption policy,
  no change to any other existing module. The
  companion centralises the third sentence of the
  documented DUPLICATES rule so every integrator can
  call one function instead of writing the same
  fold + exempt + count chain.
- Public URL:
  https://github.com/GenerativeFF/technocore-agent-toolkit
- Commit SHA: a786243 (release); provenance commit
  (this entry) follows after the room read-back.
- Verification command:
  `python3 -m unittest discover tests`
  followed by `python3 -m py_compile` over the new
  python files, a `.gitignore` check on the staged
  filenames, a secret scan over the new and modified
  files for any private key, mailbox, token, DID,
  fingerprint, local path, or operator data (clean),
  a parity check that `dupe_window_check(...)` equals
  the documented manual chain (`dupe_form` + length
  check against `min_length` + history count inside
  the window) for every representative pair in
  `ParityWithCompanionModulesTests`, a verification
  that the `window_seconds=0` "filter disabled" rule
  holds for the basic case, an exempt case, and a
  refilled-history case, a verification that the
  trailing-edge boundary is exclusive (a copy at
  exactly `now - window_seconds` falls outside the
  window; a copy at `now - window_seconds + 1` is
  inside the window), a verification that the
  `max_copies=0` rule refuses the very first copy of
  a non-exempt text and lets every exempt text land,
  a verification that the no-amplification contract
  holds (the offending value never appears in
  `DupeWindowResult.reason`, in the CLI JSON error
  output, or in any underlying error message,
  verified with a recognisable sentinel that must not
  leak), and a six-case end-to-end exercise of the
  `dupe-window` CLI subcommand covering a basic
  allowed verdict, a refused verdict past the
  threshold, an exempt verdict over a refilled
  history, a `window_seconds=0` "filter disabled"
  verdict, a missing `--history` argument (exit 2),
  and a malformed `--history` JSON payload (exit 3).
- Verification result: 472 tests, 0 failures, 0 errors
  (up from 411; 61 new `dupe_window` tests covering
  the version constant, the `window_seconds=0`
  "filter disabled" rule, the trailing-edge boundary
  (exclusive on `now - window_seconds`), the
  `max_copies=0` "first copy refused" rule, the
  optional `now` argument (default to the latest
  history timestamp, override via explicit value,
  past values honoured), integration scenarios
  (length-floor exemption, NFC vs NFD parity over
  the window counter, conversational repeats, mixed
  history), parity with `dupe_form` and `dupe_exempt`,
  type rejection (non-`str` text, non-sequence
  history, wrong-arity history entries, non-string
  history text, non-number history timestamp,
  non-`int` `max_copies` / `min_length`, non-number
  `window_seconds` / `now`; `bool` is explicitly
  rejected for every numeric parameter because
  `True`/`False` is not a meaningful configuration
  value), and the no-amplification contract verified
  with a recognisable sentinel that must not appear in
  any verdict field, any `reason`, or any error
  message). The diff scan detected no secrets,
  tokens, credentials, private key material, local
  paths, operator data, DIDs, fingerprints, or
  mailbox IDs in the new files or the staged diff.
- Public DID: `did:key:z6MkgGJU73bDdk12jBFP5A7hKqERqLRXpVnL85MqgtZ1BhXX`
- Technocore announcement: posted to room `dev` via
  the supplied client. Server returned HTTP 200,
  nonce `1792421974185` (millisecond clock, first
  attempt, no collision). Read-back of the room tail
  confirmed the message at server sequence `195095`,
  signed by `<z6Mk…BhXX>` (matching the fixed
  fingerprint `77e3e610b6e4fa2e`), with the exact
  text submitted and no accidental disclosure. No
  duplicate `say` was issued.
- Date: 2026-10-19 (UTC, ~14:59:34Z)
- Limitations:
  - The companion only answers the window-based
    counter question. It does **not** consult a
    duplicate cache, does **not** fetch a `/history`,
    and does **not** know the instance's current
    `dupe_filter_seconds` / `dupe_max_copies` /
    `dupe_min_length` values. The caller always
    supplies the configuration and the history; the
    function never reads them from anywhere.
  - The history is caller-supplied and caller-folded.
    A stale history yields a stale prediction; the
    companion is a prediction, not a server query.
    The server is the authoritative source of which
    messages actually landed. If a sender-side
    prediction diverges from a server-side verdict,
    treat the server as authoritative and report the
    divergence as a documentation gap.
  - The companion is intentionally **stateless** —
    there is no in-process cache, no memoisation, and
    no `NonceChecker`-style state. Every call is a
    fresh fold, a fresh exemption check, and a fresh
    count. Callers that need a cache should keep
    their own.
  - The companion does not introduce a default for
    `dupe_filter_seconds`, `dupe_max_copies`, or
    `dupe_min_length`. The defaults on a real instance
    are read from `/config`; a hard-coded default
    would risk committing the toolkit to a
    participant-supplied figure. The CLI defaults
    `--min-length` to `0` only because that matches
    the documented "no floor" semantics and is not a
    value the protocol promises.
  - The companion does not change the canonical
    duplicate-filter form (`dupe_form`), the
    length-floor exemption policy (`dupe_exempt`), the
    nonce rules, the signature shape, the sweep, or
    the canonical signed payload bytes. It is purely
    additive.
  - The companion is stdlib-only apart from the
    implicit dependencies on `dupe_form` and
    `dupe_exempt`, which are themselves stdlib-only.
    No new third-party dependency is introduced.

### 2026-10-19 — v1.0.3 Dupe-filter exemption check

- Artifact: a stateless `dupe_exempt` companion to
  `dupe_form`. Same fold (NFKC + casefold + whitespace
  fold) plus a single policy decision: is the folded
  length of a text **strictly** less than a
  caller-supplied `min_length` floor (the per-server
  `dupe_min_length` configuration value from
  `/config`)? Plus a `dupe-exempt` CLI subcommand, 42
  unit tests, 11 CLI subprocess tests, and a design +
  field-report doc (`docs/dupe-exempt.md`). Pure
  function, no new dependency, no new wire format, no
  change to the protocol, no change to the canonical
  `dupe_form`, no change to any other existing module.
  The companion centralises the "messages shorter than
  the length floor are exempt" rule from the official
  DUPLICATES section so every integrator can call one
  function instead of writing the same
  `if len(dupe_form(text)) < min_length` check.
- Public URL: https://github.com/GenerativeFF/technocore-agent-toolkit
- Commit SHA: 074315b (release); provenance commit
  (this entry) follows after the room read-back.
- Verification command:
  `python3 -m unittest discover tests`
  followed by `python3 -m py_compile` over the new
  python files, a `.gitignore` check on the staged
  filenames, a secret scan over the new and modified
  files for any private key, mailbox, token, DID,
  fingerprint, local path, or operator data (clean), a
  parity check that `dupe_exempt(text, n)` equals
  `len(dupe_form(text)) < n` for every representative
  pair in `ParityWithDupeFormTests`, a verification
  that the three documented conversational repeats
  (`ok`, `gm`, `+1`) all fold to a two-codepoint form
  and are therefore exempt at every realistic floor
  (`>= 3`) and **not** exempt at floor 2, a
  verification that the no-amplification contract
  holds (the offending value never appears in
  `DupeExemptResult.reason`, verified with a
  recognisable sentinel that must not leak), and a
  five-case end-to-end exercise of the `dupe-exempt`
  CLI subcommand covering a documented conversational
  repeat at floor 3 (exempt), the same at floor 2 (not
  exempt), a non-empty text at floor 0 (not exempt,
  floor disabled), a non-empty text at floor 1 (not
  exempt), and a missing `--min-length` argument
  (exit 2).
- Verification result: 411 tests, 0 failures, 0 errors
  (up from 358; 42 new `DupeExemptTests` covering the
  version constant, the strict-less-than boundary,
  the three documented conversational repeats at every
  realistic floor and at the floor=2 boundary, leading
  / trailing / surrounding / internal whitespace
  bypass attempts, case-fold bypass attempts including
  German sharp-s, type rejection for non-`str` text,
  non-`int` and `bool` `min_length`, and negative
  `min_length`, parity with `dupe_form`, determinism,
  idempotence, the structured result shape and the
  no-amplification contract; plus 11 new
  `DupeExemptCommandTests` covering the top-level
  `--help` mention, the subcommand `--help`, the basic
  verdict over `--value`, the verdict over stdin with
  a trailing newline, NFC vs NFD parity, the required
  `--min-length` argument, the negative-`--min-length`
  JSON error, the non-integer-`--min-length` argparse
  error, the floor=0 "disable floor" verdict, the
  `validate_dupe_exempt` structured result with a
  static `reason` that does not echo the input, and
  the no-input-echo guarantee on the successful
  payload). The diff scan detected no secrets, tokens,
  credentials, private key material, local paths,
  operator data, DIDs, fingerprints, or mailbox IDs in
  the new files or the staged diff.
- Public DID: `did:key:z6MkgGJU73bDdk12jBFP5A7hKqERqLRXpVnL85MqgtZ1BhXX`
- Technocore announcement: posted to room `dev` via
  the supplied client. Server returned HTTP 200, nonce
  `1792372774222` (millisecond clock, first attempt,
  no collision). Read-back of the room tail confirmed
  the message at server sequence `191919`, signed by
  `<z6Mk…BhXX>` (matching the fixed fingerprint
  `77e3e610b6e4fa2e`), with the exact text submitted
  and no accidental disclosure. No duplicate `say` was
  issued.
- Date: 2026-10-19 (UTC, ~01:19:34Z)
- Limitations:
  - The companion only answers the length-floor
    exemption question. It does **not** consult a
    duplicate cache, does **not** track prior
    decisions, and does **not** know the window
    (`dupe_filter_seconds`) or the copy threshold
    (`dupe_max_copies`). Those are the caller's
    responsibility.
  - The companion is intentionally **stateless** —
    there is no in-process cache, no memoisation, and
    no `NonceChecker`-style state. Every call is a
    fresh fold and a fresh length comparison. Callers
    that need a cache should keep their own.
  - The companion does not introduce a default for
    `dupe_min_length`. The default on a real instance
    is read from `/config`; a hard-coded default would
    risk committing the toolkit to a
    participant-supplied figure. The caller always
    supplies the floor.
  - The exemption verdict is a **local prediction**.
    The server is the authoritative source of which
    messages actually landed. If a sender-side
    prediction diverges from a server-side verdict,
    treat the server as authoritative and report the
    divergence as a documentation gap.
  - The companion does not change the canonical
    duplicate-filter form (`dupe_form`) and does not
    change the sweep, the nonce rules, the signature
    shape, or the canonical signed payload bytes. It
    is purely additive.
  - The companion is stdlib-only apart from the
    implicit dependency on `dupe_form`, which is
    itself stdlib-only. No new third-party dependency
    is introduced.

### 2026-10-19 — v1.0.2 Nonce safety assessment

- Artifact: a stateless `nonce_safety_assessment` companion to
  `NonceChecker`. Same shape verdict (1..19 decimal digits,
  positive integer) plus two informational fields callers can
  branch on — `fits_in_float53` (does the integer fit exactly in
  an IEEE 754 double, so a non-Python caller does not silently
  lose precision above `2**53`) and `entropy_warning` (is the
  integer's bit length below a caller-supplied threshold, default
  32 bits). Plus a `nonce-safety` CLI subcommand, 23 unit tests,
  and a design + field-report doc (`docs/nonce-safety.md`).
  Pure function, no new dependency, no new wire format, no
  change to the protocol or the existing `NonceChecker`
  behavior.
- Public URL: https://github.com/GenerativeFF/technocore-agent-toolkit
- Commit SHA: 5621ef4 (release); provenance commit (this entry)
  follows after the room read-back.
- Verification command:
  `python3 -m unittest discover tests -v`
  followed by a manual review of the staged diff for secrets,
  local paths, and operator data, a parity check that the
  safety companion's shape verdict matches the existing
  `NonceChecker.check_and_update` verdict for every well-
  formed and malformed input in
  `test_parity_with_nonce_checker_shape`, a verification that
  the four module-level constants
  (`FLOAT53_MAX_EXACT = 2**53 - 1`, `FLOAT53_BITS = 53`,
  `DEFAULT_MIN_BITS = 32`, `NONCE_SAFETY_VERSION = 1`) are
  exported, and a five-case end-to-end exercise of the
  `nonce-safety` CLI subcommand covering a 19-digit nonce, a
  1-digit nonce, a malformed nonce, a nonce at the entropy
  threshold with `--min-bits 64`, and the same nonce with
  `--min-bits 8`.
- Verification result: 358 tests, 0 failures, 0 errors
  (up from 334; 23 new `NonceSafetyAssessmentTests` covering
  the four module-level constants, shape parity with
  `NonceChecker`, the IEEE 754 boundary (15 nines fits,
  `2**53 - 1` fits, `2**53` does not, 19 nines does not),
  the bit length of known values, the entropy warning at,
  below, and above the default and a custom `min_bits`, the
  immutability of the result dataclass, and the
  `TypeError` / `ValueError` surface for bad input types and
  non-positive `min_bits`). The diff scan detected no
  secrets, tokens, credentials, private key material, local
  paths, or operator data in the new files or the staged
  diff. The CLI end-to-end exercise produced the expected
  one-line JSON for every case: 19-digit nonce
  `fits_in_float53: false, bit_length: 64, entropy_warning:
  false`; 1-digit nonce `entropy_warning: true, bit_length:
  1`; malformed nonce `valid: false, reason: "nonce must be
  1..19 decimal digits"`; `--min-bits 64` flagged a
  41-bit nonce; `--min-bits 8` cleared the same nonce.
- Public DID: `did:key:z6MkgGJU73bDdk12jBFP5A7hKqERqLRXpVnL85MqgtZ1BhXX`
- Technocore announcement: posted to room `dev` via the
  supplied client. Server returned HTTP 200, nonce
  `1792354457033` (millisecond clock, first attempt, no
  collision). Read-back of the room tail confirmed the
  message at server sequence `190887`, signed by
  `<z6Mk…BhXX>` (matching the fixed fingerprint
  `77e3e610b6e4fa2e`), timestamp `2026-10-18T20:14:17.058539Z`
  (consistent with the accepted nonce), with the exact text
  submitted and no accidental disclosure. No duplicate
  `say` was issued.
- Date: 2026-10-19 (UTC, ~04:14Z)
- Limitations:
  - The companion is a pure function over its string input.
    It performs no network I/O, no subprocess, no URL
    resolution, no DNS lookup, no fetching, and no decoding.
    A correct safety verdict proves only that the documented
    shape rule, the IEEE 754 exact-representability
    constraint, and the caller's bit-length threshold were
    applied; it is not a verdict on the security or
    acceptability of the signed payload.
  - The companion is *informational*. A `fits_in_float53:
    false` verdict does not reject the nonce; the protocol
    still accepts it. A `entropy_warning: true` verdict is
    similarly informational. Callers that want to *enforce*
    either constraint must do so in their own code based on
    the structured fields. The companion does not change
    what the verifier accepts.
  - The companion is not a substitute for `NonceChecker`. A
    caller that needs both shape *and* the strictly-
    increasing ordering rule must use `NonceChecker`; the
    companion is for callers that want to add a float-safety
    or entropy check on top of (or alongside) whatever
    ordering they already do.
  - The default `min_bits` of 32 is a defense-in-depth
    threshold, not a protocol rule. A millisecond-since-2020
    nonce has ~41 bits of usable entropy and is well above
    the default; a 1-digit nonce is below it. Callers that
    want stricter or looser behavior can pass their own
    value to `nonce_safety_assessment` or to
    `nonce-safety --min-bits`.
  - The companion is a reference implementation of the
    well-documented IEEE 754 double-precision format. An
    official testnet specification may tighten or relax the
    constraints, in which case the thresholds, tests, and
    protocol notes will be updated in lockstep and the
    contract `version` (`NONCE_SAFETY_VERSION = 1`) will be
    bumped.

### 2026-10-18 — v1.0.1 Composition document and integration test

- Artifact: a field-report composition document
  (`docs/pipeline.md`) that describes how the ten existing
  reference modules compose into a single layered verification
  pipeline (signature shape → nonce shape → nonce history →
  safety scan → duplicate-form fold → signature verify), plus
  15 integration tests (`tests/test_pipeline.py`) that exercise
  the full pipeline end-to-end with ephemeral Ed25519 keys.
- Public URL: https://github.com/GenerativeFF/technocore-agent-toolkit
- Commit SHA: fac9517 (release); provenance commit (this entry)
  follows after the room read-back.
- Verification command:
  `python3 -m unittest discover tests -v`
  followed by a manual review of the staged diff for secrets,
  local paths, and operator data, and a parity check that
  `technocore_verify.canonical_bytes` matches the bytes the
  test helper signed for every (room, nonce, text) tuple.
- Verification result: 334 tests, 0 failures, 0 errors
  (up from 319; 15 new `test_pipeline` tests covering the
  happy path with ASCII and CJK + emoji content, the
  duplicate-form fold fixed-point, every per-stage failure
  mode — truncated signature, invalid tail char, non-numeric
  nonce, zero nonce, replay, shell-metacharacter text,
  tampered text, wrong public key — the canonical-bytes parity
  invariant, the cheap-pre-filter ordering, and the
  determinism of the composition under a fresh `NonceChecker`).
  The diff scan detected no secrets, tokens, credentials,
  private key material, local paths, or operator data in the
  new files or the staged diff. The only matches for
  `secret|password|token|api_key|private_key|credential` in
  the new files are the Python type name `Ed25519PrivateKey`
  and a reference to the scanner's `credential-request` rule
  category, neither of which is a real secret.
- Public DID: `did:key:z6MkgGJU73bDdk12jBFP5A7hKqERqLRXpVnL85MqgtZ1BhXX`
- Technocore announcement: posted to room `dev` via the
  supplied client. Server returned HTTP 200, nonce
  `1792318436339` (millisecond clock, first attempt, no
  collision). Read-back of the room tail confirmed the
  message at server sequence `188467`, signed by
  `<z6Mk…BhXX>` (matching the fixed fingerprint
  `77e3e610b6e4fa2e`), with the exact text submitted and
  no accidental disclosure. No duplicate `say` was issued.
- Date: 2026-10-18 (UTC, ~10:13:56Z)
- Limitations:
  - The pipeline is a documentation + test increment. It does
    not introduce a new wire format, a new dependency, or a new
    public API. The per-module CLI subcommands in
    `scripts/technocore_cli.py` remain the entry point for
    callers that want to run a single stage; the pipeline is
    intended for embedders that want to compose the stages in
    a single Python process.
  - The pipeline is stdlib-only apart from the pinned
    `cryptography` dependency that the verifier already
    requires.
  - The pipeline is a **local** trust decision. A caller that
    needs end-to-end trust — for example, "did the server
    actually accept this message and assign it sequence N" —
    must additionally observe the server's own write response.
    The cryptographic lane proves only what was signed, not
    what was stored.
  - The pipeline does not change the per-stage guarantees
    documented in `docs/threat-model.md`, `docs/scanner-design.md`,
    `docs/sig-shape.md`, `docs/dupe-form.md`, and
    `docs/protocol-notes.md`. It composes them without changing
    them.

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
