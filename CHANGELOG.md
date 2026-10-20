# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and the project adheres to [Semantic Versioning](https://semver.org/).

## [1.0.6] — 2026-10-20

### Added
- `src/technocore_binding.py`: the signed-field binding surface —
  a report of **which fields of a room record the signature
  actually covers**. The canonical signed byte string is
  `("<room>|<nonce>|<swept text>").encode("utf-8")`, so exactly
  three fields are inside the signature while the read API returns
  six. The module splits them into three classes:
  - `SIGNED_FIELDS` = `("room", "nonce", "text")` — inside the
    signature;
  - `SERVER_ASSERTED_FIELDS` = `("ts", "seq")` — stamped by the
    server after accepting the write and **not** covered by the
    signature, so a verifying signature makes no claim about
    composition time or room ordering;
  - `IDENTITY_FIELDS` = `("from", "did")` — the signer, bound to
    the verifying key rather than to the signed bytes.
  Two entry points:
  - `binding_report(record, *, room=None)` — returns a frozen
    `BindingReport` with `ok`, static `reason`, `signed_fields`,
    `unsigned_server_fields`, `identity_field`, `room`, `nonce`,
    `canonical_length`, `canonical_sha256`, static `warnings`, and
    `version`. The canonical hash is taken from
    `technocore_verify.canonical_bytes`, so the canonical form
    keeps exactly one source of truth and the SHA matches
    `VerifyResult.canonical_sha256`.
  - `to_verifier_payload(record, *, room=None)` — normalizes a
    server record into the five-field mapping
    `technocore_verify.verify` consumes: renames `from` to `did`,
    re-encodes the integer `nonce` the read API returns into the
    decimal string the signature was computed over, and
    **deliberately drops `ts` and `seq`** so a caller cannot
    mistake them for authenticated data. Never mutates its input.
  Interoperability hazards are reported as static warnings rather
  than errors: the read API spelling `from`, the integer `nonce`
  (including a float53 precision warning above `2**53 - 1`, linking
  to the v1.0.2 nonce safety assessment), and a record that omits
  `room`. A `float` or `bool` nonce is rejected outright rather
  than coerced, because by the time a caller holds a float the
  precision may already be lost. `BindingError` (a `ValueError`)
  is raised when a record cannot be normalized.
  Pure functions: no network I/O, no subprocess, no decoding, no
  cryptographic verification claim. A passing report is a
  statement about the canonical form, not an assertion that a
  signature verifies.
- `scripts/technocore_cli.py`: a new `binding` subcommand. Reads
  the record from `--record` (a JSON path) or stdin (`--record -`,
  or by omitting the flag), accepts `--room` for records that omit
  one, accepts a bare array or a read-API `{"messages": [...]}`
  envelope, and uses the envelope's top-level `room` when the
  inner message omits one (an explicit `--room` wins). Emits one
  JSON line naming `signed_fields` and `unsigned_server_fields`;
  exit 2 with a JSON error line on stderr for malformed input.
- `docs/binding.md`: design doc covering the three-way field
  model, the interface, the CLI, the security boundary, the
  acceptance tests, and the limitations.
- `tests/test_binding.py`: 68 unit tests.
- `tests/test_cli.py`: 18 `BindingCommandTests` subprocess tests.

### Notes
- This milestone adds no dependency, changes no wire format, and
  modifies no existing module. `technocore_verify.canonical_bytes`
  is imported, not reimplemented.

## [1.0.5] — 2026-10-20

### Added
- `src/technocore_dupe_decision.py`: a thin orchestrator
  over `dupe_form`, `dupe_exempt`, and `dupe_window_check`
  that answers the documented three-step question the
  `DUPLICATES` section asks every sender to answer —
  *would this text land, or would the window-based 5-copy
  counter refuse it?* Pure function (no state, no network
  I/O) with two entry points:
  - `dupe_decision(text, history, *, window_seconds,
    max_copies, min_length=0, now=None)` — returns
    `True` when the text would land under the documented
    three-step policy, `False` when it would be refused.
    The function applies the three legs in the documented
    order (disabled-filter short-circuit,
    length-floor exemption, window counter) and matches the
    manual chain every integrator would otherwise write.
  - `validate_dupe_decision(text, history, *,
    window_seconds, max_copies, min_length=0, now=None)`
    — returns a structured `DupeDecisionResult` with
    `valid`, `would_land`, `refused`, `filter_active`,
    `folded`, `folded_length`, `exempt`,
    `copies_in_window`, `min_length`, `max_copies`,
    `window_seconds`, `reason` (static, parameter-free),
    and the version constants. The structured result
    mirrors the input-validation surface of the underlying
    companions.
  Module-level constants `DUPE_DECISION_VERSION = 1` and
  `DUPE_DECISION_WINDOW_VERSION` (aliased to
  `DUPE_WINDOW_VERSION`) are exported so callers can pin
  against the orchestrator and detect any silent drift
  in the underlying window companion.
  `DupeDecisionHistoryEntry` is exported as a stable
  type alias for the `(text, timestamp)` history shape.
- `scripts/technocore_cli.py`: a new `dupe-decision`
  subcommand that wraps the orchestrator. Reads the text
  from `--value` or stdin (one trailing newline stripped)
  and reads the history from `--history` (a path to a
  JSON file) or stdin (`--history -`, the same
  convention as `--file`). Accepts required
  `--window-seconds` (non-negative number), required
  `--max-copies` (non-negative integer), optional
  `--min-length` (non-negative integer, defaults to
  `0` for "no floor"), and optional `--now` (Unix
  seconds). Emits the same one-line JSON contract as the
  rest of the CLI; exit codes match (`0` for success,
  `2` for argument validation, `3` for content
  validation).
- `docs/dupe-decision.md`: a design + field report
  describing the problem (the three-step policy the
  `DUPLICATES` section asks the sender to apply), the
  intended audience (bridges, relays, log replayers,
  conformance harnesses), the interface (Python API +
  CLI), the three legs in detail (disabled-filter
  short-circuit, length-floor exemption, window
  counter), the history shape, the security boundary,
  the acceptance tests, the limitations, and the
  versioning policy. The orchestrator does not change
  any underlying companion; it only sequences them.

### Tests
- `tests/test_dupe_decision.py`: 77 new unit tests
  covering the version constants, the documented
  ordering of the three legs (disabled-filter
  short-circuit, length-floor exemption, window
  counter), the equivalence of `dupe_decision` with
  the manual three-step chain every integrator writes
  (`ParityWithManualChainTests`), the parity of
  `validate_dupe_decision` with the underlying
  companions (`ParityWithCompanionModulesTests`), the
  no-amplification contract (verified with a
  recognisable sentinel that must not appear in any
  structured field, the `reason`, or any error
  message), the type-rejection surface (non-`str`
  text, non-sequence history, wrong-arity history
  entries, non-string history text, non-number
  history timestamp, non-`int` `max_copies` /
  `min_length`, non-number `window_seconds` / `now`;
  `bool` is explicitly rejected for every numeric
  parameter), the structured-result immutability and
  echo-back (`ResultShapeTests`), the determinism of
  repeated calls (`DeterminismTests`), the documented
  `/llms.txt` scenario (`DocumentedScenarioTests` —
  5-copy / 120s boundary), and the public surface
  (`SurfaceTests`). Three pre-existing assertions in
  the contract fixture that contradicted the parity
  contract (`test_python_api_determinism`,
  `test_invalid_history_entry_does_not_echo_value`,
  `test_invalid_text_does_not_echo_value`) were
  corrected in this commit; the corrections are
  documented in the test file's comments and convert
  the failing blocks from assertions that violated
  the documented three-step policy into assertions
  that align with the parity contract (no coverage
  was lost — `test_invalid_text` and
  `test_invalid_history_entry_arity` already pin the
  rejection paths, and
  `test_no_amplification_on_validator_reasons`
  already pins the no-amplification contract).
- `tests/test_cli.py`: a new
  `DupeDecisionCommandTests` class exercising the
  subcommand end-to-end: the top-level `--help`
  mention, the subcommand `--help` (every flag
  documented), the empty-history lands verdict, the
  third-copy-lands / fourth-copy-refused boundary on
  the documented `max_copies=3` value, the
  disabled-filter short-circuit with a refilled
  history, the length-floor exemption with a
  refilled history, the value-via-stdin and
  history-via-stdin (`--history -`) conventions, the
  missing-flag paths (`--window-seconds`,
  `--max-copies`) at exit `2`, a negative
  `--window-seconds` rejected at exit `2` without
  echoing the offending value, a non-list
  `--history` JSON rejected at exit `3`, the
  NFC-vs-NFD parity over the full pipeline, and the
  no-amplification contract on the JSON payload.

### Security
- The orchestrator is a pure function over its inputs.
  No network I/O, no subprocess execution, no
  filesystem writes, no signing, no posting, no
  DNS, no fetching, no decoding, and no
  consultation of any server-side cache or `/config`
  endpoint. The caller supplies the window, the
  copy threshold, the length floor, and the
  history; the orchestrator does not read any of
  them from anywhere.
- The structured result never echoes the input
  `text` on any channel; `folded` is the transformed
  output of `dupe_form`, not the input. Errors and
  rejection reasons are static, parameter-free
  strings; the offending value is never surfaced.

## [1.0.4] — 2026-10-19

### Added
- `src/technocore_dupe_window.py`: a stateless `dupe_window_check`
  companion to `dupe_form` and `dupe_exempt`. Pure function (no
  state, no network I/O) that returns `True` when a text would be
  refused by the server's window-based duplicate-filter counter
  given the caller-supplied recent copy history, the
  caller-supplied window, the caller-supplied copy threshold,
  the caller-supplied length floor, and an optional `now`
  reference. The companion also exposes a `validate_dupe_window`
  wrapper that returns a structured `DupeWindowResult` with:
  - `valid` — True only when every input is well-typed and
    `window_seconds` / `max_copies` / `min_length` are
    non-negative;
  - `refused` — the verdict (True only when the text is not
    exempt and the count of matching history entries inside
    the window has reached `max_copies`);
  - `folded` — the canonical duplicate-filter form of `text`;
  - `copies_in_window` — the number of history entries whose
    folded form equals `folded` and whose timestamp falls
    inside `window_seconds` of `now` (exclusive on the
    trailing edge);
  - `max_copies`, `window_seconds` — echoed back because they
    are caller-supplied configuration values;
  - `reason` — a static, parameter-free string set only when
    `valid` is False; never echoes the input value.
  Module-level constant `DUPE_WINDOW_VERSION = 1` is exported
  for callers that want to pin against it.
- `scripts/technocore_cli.py`: a new `dupe-window` subcommand
  that wraps the companion. Reads the text from `--value` or
  stdin (one trailing newline stripped) and reads the history
  from `--history` (a path to a JSON file) or stdin
  (`--history -`, the same convention as `--file`). Accepts
  required `--window-seconds` (non-negative number) and
  `--max-copies` (non-negative integer), optional
  `--min-length` (non-negative integer, defaults to `0` for
  "no floor"), and optional `--now` (Unix seconds). Emits the
  same one-line JSON contract as the rest of the CLI; exit
  codes match (`0` for success, `2` for argument validation,
  `3` for content validation).
- `docs/dupe-window.md`: a design + field report describing
  the problem (per-server `dupe_filter_seconds` /
  `dupe_max_copies` / `dupe_min_length` window policy), the
  interface, the history shape, the CLI surface, the
  security boundary, the acceptance tests, and the
  limitations. The companion does not change the protocol
  and does not change the canonical duplicate-filter form
  or the length-floor exemption policy; it only answers
  the "would this text be refused by the window-based
  counter right now?" question with a stable verdict.

### Tests
- `tests/test_dupe_window.py`: 61 new unit tests covering
  the version constant, the `window_seconds=0` "filter
  disabled" rule, the trailing-edge boundary (exclusive on
  `now - window_seconds`), the `max_copies=0` "first copy
  refused" rule, the optional `now` argument (default to
  the latest history timestamp, override via explicit
  value, past values honoured), integration scenarios
  (length-floor exemption, NFC vs NFD parity over the
  window counter, conversational repeats, mixed-history
  cases), parity with `dupe_form` and `dupe_exempt`, type
  rejection (non-`str` text, non-sequence history,
  wrong-arity history entries, non-string history text,
  non-number history timestamp, non-`int` `max_copies` /
  `min_length`, non-number `window_seconds` / `now`; `bool`
  is explicitly rejected for every numeric parameter
  because `True`/`False` is not a meaningful configuration
  value), and the no-amplification contract (verified with
  a recognisable sentinel that must not appear in any
  verdict field, any `reason`, or any error message).
- `tests/test_cli.py`: a new `DupeWindowCommandTests`
  class exercising the subcommand end-to-end: the
  top-level `--help` mention, the subcommand `--help`,
  the basic verdict over `--value` and `--history`, the
  same verdict over stdin with a trailing newline, the
  history-from-stdin (`--history -`) path, the
  history-from-JSON-file path, a missing `--history`
  rejected at exit 2, a malformed `--history` rejected
  at exit 3 with an error that does not echo the
  offending bytes, a wrong-arity history entry rejected
  at exit 3 with a static message, a negative
  `--window-seconds` / `--max-copies` / `--min-length`
  rejected at exit 2 with a JSON error that does not
  echo the offending value, a non-integer
  `--max-copies` rejected at exit 2 by argparse, the
  `window_seconds=0` "filter disabled" verdict, the
  `min-length` exemption parity with the `dupe-exempt`
  subcommand, and the no-input-echo guarantee on the
  successful payload.

### Security
- The companion never echoes the input `text` on any
  channel. `folded` is the *transformed* output;
  `window_seconds`, `max_copies`, and `min_length` are
  caller-supplied configuration values; `reason` is a
  static string.
- The companion does not consult any server-side cache,
  read `/config`, fetch `/history`, perform network I/O,
  perform subprocess I/O, or perform filesystem I/O
  beyond reading the optional `--value` / `--history` /
  stdin.
- The companion does not introduce a default for
  `dupe_filter_seconds`, `dupe_max_copies`, or
  `dupe_min_length`. The CLI defaults `--min-length` to
  `0` only because that matches the documented "no
  floor" semantics and is not a value the protocol
  promises. The window and the threshold are always
  required because the documented "0 on the window
  disables the filter" rule would make a default unsafe.

## [1.0.3] — 2026-10-19

### Added
- `src/technocore_dupe_exempt.py`: a stateless `dupe_exempt`
  companion to `dupe_form`. Pure function (no state, no network
  I/O) that returns a structured `DupeExemptResult` with:
  - `valid` — True only when `text` is a `str` and `min_length`
    is a non-negative integer (`TypeError`/`ValueError` raised
    for bad input types and negative `min_length`; `bool` is
    explicitly rejected as a `min_length` because `True`/`False`
    is not a meaningful length floor);
  - `exempt` — whether the *folded* length of `text` is
    **strictly** less than `min_length` (the documented
    "shorter than the length floor" rule);
  - `folded` — the canonical duplicate-filter form of `text`
    (the same value `dupe_form(text)` would return);
  - `folded_length` — codepoint count of the folded form;
  - `min_length` — the floor the caller supplied, echoed back
    for logging;
  - `reason` — a static, parameter-free string set only when
    `valid` is False; never echoes the input value.
  Module-level constant `DUPE_EXEMPT_VERSION = 1` is exported
  for callers that want to pin against it.
- `scripts/technocore_cli.py`: a new `dupe-exempt` subcommand
  that wraps the companion. Reads the text from `--value` or
  stdin (one trailing newline stripped) and accepts a required
  `--min-length` integer. Emits the same one-line JSON contract
  as the rest of the CLI; exit codes match (`0` for success,
  `2` for argument validation, `3` for content validation).
- `docs/dupe-exempt.md`: a design + field report describing
  the problem (per-server `dupe_min_length` floor exemption
  policy), the interface, the security boundary, the
  acceptance tests, and the limitations. The companion does
  not change the protocol and does not change the canonical
  duplicate-filter form; it only answers the
  "would this text be exempt from the length floor?"
  question with a stable verdict.

### Tests
- `tests/test_dupe_exempt.py`: 42 new unit tests covering
  the version constant, the strict-less-than boundary
  (including the floor=0 "every message exempt" case and
  the floor=floor "equal not exempt" case), the three
  documented conversational repeats (`ok`, `gm`, `+1`) at
  realistic floors and at the floor=2 boundary, whitespace
  bypass attempts (leading, trailing, internal, surrounding),
  case-fold bypass attempts (`OK` vs `ok`, German sharp-s),
  type rejection (non-`str` text, non-`int`/`bool`
  `min_length`, negative `min_length`), parity with
  `dupe_form`, determinism, idempotence, the structured
  result shape, and the no-amplification contract
  (verified with a recognisable sentinel that must not
  appear in any error field).
- `tests/test_cli.py`: 11 new subprocess tests in
  `DupeExemptCommandTests` covering the top-level `--help`
  mention, the subcommand `--help`, the basic verdict
  over `--value`, the verdict over stdin with a trailing
  newline, NFC vs NFD parity, the required `--min-length`
  argument, the negative-`--min-length` JSON error, the
  non-integer-`--min-length` argparse error, the floor=0
  "disable floor" verdict, and the no-input-echo
  guarantee on the successful payload.

### Security
- The companion never echoes the input `text` on any
  channel. `reason` is a static string; `folded` and
  `folded_length` are the *transformed* output; `min_length`
  is a non-negative integer the caller supplied.
- The companion does not consult any server-side cache,
  read `/config`, perform network I/O, perform subprocess
  I/O, or perform filesystem I/O beyond reading the
  optional `--value` / stdin.
- The companion does not introduce a default for
  `dupe_min_length`. The caller always supplies the floor,
  so the toolkit is not committed to a participant-supplied
  figure for a per-server configuration value.

## [1.0.2] — 2026-10-19

### Added
- `src/technocore_nonce.py`: a stateless `nonce_safety_assessment`
  companion to `NonceChecker`. Pure function (no state, no network
  I/O) that returns a structured `NonceSafetyResult` with:
  - `valid` — same shape verdict as `NonceChecker.check_and_update`
    (1..19 decimal digits, positive integer; unicode-digit and
    empty/oversize inputs rejected; `TypeError`/`ValueError` raised
    for bad input types and non-positive `min_bits`);
  - `fits_in_float53` — whether the integer value is exactly
    representable in an IEEE 754 double (`<= 2**53 - 1`);
  - `bit_length` — the bit length of the integer value;
  - `entropy_warning` — whether the bit length is below the
    caller-supplied `min_bits` threshold (default 32);
  - `version` — the contract version of the safety assessment
    API (`NONCE_SAFETY_VERSION = 1`).
  Module-level constants `FLOAT53_MAX_EXACT`, `FLOAT53_BITS`, and
  `DEFAULT_MIN_BITS` are exported for callers that want to pin
  against them.
- `scripts/technocore_cli.py`: a new `nonce-safety` subcommand
  that wraps the companion. Reads the nonce from `--value` or
  stdin (one trailing newline stripped) and accepts an optional
  `--min-bits` integer. Emits the same one-line JSON contract as
  the rest of the CLI; exit codes match.
- `docs/nonce-safety.md`: a design + field-report document
  describing the problem (float precision loss above `2**53`, low
  entropy for short nonces), the interface, the security
  boundary, the acceptance tests, and the limitations. The
  companion does not change the protocol and does not change the
  shape verdict of `NonceChecker`; it only adds two informational
  fields a caller can branch on.

### Tests
- `tests/test_nonce.py`: 23 new `NonceSafetyAssessmentTests`
  covering the four module-level constants, shape parity with
  `NonceChecker`, the IEEE 754 boundary (15 nines fits, `2**53-1`
  fits, `2**53` does not, 19 nines does not), the bit length of
  known values, the entropy warning at/below/above the default
  and a custom `min_bits`, the immutability of the result
  dataclass, and the `TypeError`/`ValueError` surface for bad
  input types and non-positive `min_bits`. The shape verdict of
  the safety assessment is checked for parity with
  `NonceChecker.check_and_update` for eight inputs.

### Documentation
- `README.md`: the `Status` and `What's inside` tables now
  reference the new `nonce-safety` companion and the design doc.

### Security
- No private key material, credentials, operator data, local
  paths, or infrastructure details appear in the new files. The
  companion is a pure function over its string input; it does
  not perform network I/O, subprocess execution, or filesystem
  writes.

## [1.0.1] — 2026-10-18

### Added
- `docs/pipeline.md`: a field-report composition document that
  shows how the ten existing reference modules compose into a
  single layered verification pipeline (signature shape → nonce
  shape → nonce history → safety scan → duplicate-form fold →
  signature verify). The document states the audience, the
  per-stage guarantees, the per-stage non-guarantees, the trust
  boundary, the failure-handling contract, and a reproducible
  check. No new wire format, no new dependency, no new public
  API.
- `tests/test_pipeline.py`: 15 integration tests that exercise
  the full pipeline end-to-end with ephemeral Ed25519 keypairs.
  The suite covers:
  - the happy path (a well-formed payload passes every stage
    and reaches the cryptographic verify),
  - CJK + emoji content (the pipeline handles non-ASCII text
    that the sweep must not touch),
  - the duplicate-form fold fixed-point
    (`dupe_form(dupe_form(x)) == dupe_form(x)`),
  - stage-1 (signature shape) catches a truncated signature
    and a signature with an invalid tail character,
  - stage-2 (nonce shape) catches a non-numeric and a zero
    nonce,
  - stage-3 (nonce history) catches a replay of the same
    payload,
  - stage-4 (safety scan) catches shell-metacharacter text,
  - stage-6 (signature verify) catches a tampered text and a
    wrong public key,
  - the canonical-bytes parity invariant
    (`canonical_bytes(room, nonce, sweep(text))` matches the
    bytes the helper signed),
  - the cheap pre-filter runs before the cryptographic check
    and never requires the cryptography stack,
  - the pipeline is pure (re-running on the same input yields
    the same verdict with a fresh `NonceChecker`).

### Documentation
- The `docs/pipeline.md` document is referenced from the
  README's table so a new reader can find it next to the
  per-module docs.

### Security
- No private key material, credentials, operator data, local
  paths, or infrastructure details appear in the new files.
  All test keys are generated in-memory by the test process and
  are never serialised to disk.

## [1.0.0] — 2026-10-18

### Added
- `src/technocore_dupe_form.py`: pure-Python reference
  implementation of the *comparison* form the 5-copy 422
  counter uses (NFKC + `str.casefold()` + whitespace fold,
  applied in that order to the post-sweep text). The module
  exposes a stable API:
  - `dupe_form(text) -> str` — pure function. Applies
    `unicodedata.normalize("NFKC", text)`,
    `text.casefold()`, and `" ".join(text.split())`. Raises
    `TypeError` if `text` is not a `str`.
  - `validate_dupe_form(text) -> DupeFormResult` — structured
    verdict with a static, parameter-free `reason` field that
    never echoes the input value.
  - `DupeFormResult` — frozen dataclass with `valid`,
    `folded`, and `reason` fields.
  - `DupeFormError` — exception class for callers that want
    to raise their own static-message errors.
  - `DUPE_FORM_VERSION = 1` — integer version of the
    contract.
- `tests/test_dupe_form.py`: 54 unit tests covering the NFKC
  fold (NFC vs NFD, fullwidth letters, circled numbers,
  emoji preservation), the case fold (lowercase, mixed case,
  German sharp-s, Greek final sigma, accented letters,
  conversational repeats), the whitespace fold (ASCII space,
  tab, newline, Unicode whitespace, mixed), idempotence,
  determinism, the type-rejection matrix (`bytes`, `int`,
  `float`, `bool`, `list`, `dict`, `None`), the
  no-amplification contract (the validator never echoes the
  input value in any error or reason channel), the signed
  vs comparison form contract (NFC and NFD have different
  signed bytes — 6 vs 8 raw bytes for "Việt"), and the
  documented "Việt" example.
- `tests/test_cli.py`: 16 new CLI subprocess tests for the
  `dupe-form` subcommand covering basic fold via `--value`
  and via stdin, NFC/NFD collapse, German sharp-s fold,
  circled-numbers fold, whitespace fold, empty string,
  whitespace-only input, trailing-newline stripping,
  single-line JSON output, CLI-level idempotence, CLI-level
  determinism (50-call loop), no-amplification in stderr,
  and a documentation guard ("comparison" and "signed"
  appear in the top-level `--help`).
- `scripts/technocore_cli.py`: new `dupe-form` subcommand
  that reads a text from `--value` or stdin (with one
  trailing newline stripped) and emits one JSON object on
  stdout with `valid`, `folded` (only when valid), and
  `version` fields. The top-level `--help` now lists
  `dupe-form` alongside the existing subcommands.
- `docs/dupe-form.md`: design notes for the duplicate-filter
  canonical form, including the problem statement, the
  audience, the public interface, the security boundary,
  the rationale for choosing NFKC over NFC/NFD, the
  rationale for choosing `str.casefold()` over
  `str.lower()`, the documented "Việt" example, the
  conversational-repeat exemption, the acceptance test
  list, the out-of-scope list, the versioning policy, and
  the limitations.

### Notes
- Resolves the dev-room seq 187057 ambiguity about the
  canonical normalisation form: the server never normalizes
  the *signed / stored* bytes (per NORMALIZATION), but the
  5-copy counter normalizes the *comparison* form (per
  DUPLICATES) as "case, whitespace and Unicode compatibility
  folded". The reference implementation follows the
  standard Python interpretation: NFKC for compatibility
  fold, `str.casefold()` for case fold, and
  `" ".join(text.split())` for whitespace fold.
- The fold is a pure function over a Python `str`. It
  performs no network I/O, no subprocess, no URL
  resolution, no DNS lookup, no fetching, and no decoding
  of the input beyond the documented transformations.
- The fold is idempotent: `dupe_form(dupe_form(x)) ==
  dupe_form(x)` for every legal `x`.
- The fold does not enforce the documented length floor
  (`dupe_min_length`). Conversational repeats that are
  exempt at the server are still folded here; callers
  compare the folded length to the configured floor.

## [0.9.0] — 2026-10-18

### Added
- `src/technocore_sig_shape.py`: pure-Python reference
  implementation of the *surface* canonical form of a Technocore
  signature. The validator checks four structural invariants and
  exposes a stable API:
  - `is_canonical_signature_shape(candidate) -> bool` — fast,
    allocation-light predicate.
  - `validate_signature_shape(candidate) -> SigShapeResult` —
    structured verdict with a static, parameter-free `reason`
    field that never echoes the input.
  - `EXPECTED_LENGTH = 86` — the canonical unpadded base64url
    length of a 64-byte Ed25519 signature
    (`ceil(64 * 8 / 6) = 86`).
  - `TAIL_CHARS = ("A", "Q", "g", "w")` — the four reachable
    last-character values for a 64-byte tail; the low 4 bits of
    the final 6-bit group are always zero, leaving exactly four
    reachable characters at the tail position.
  - `ALLOWED_CHARS` — frozenset of the unpadded base64url
    alphabet.
  - `SIG_SHAPE_VERSION = 1` — integer version of the contract.
  - `SigShapeError` — exception class for callers that want to
    raise their own static-message errors.
- `tests/test_sig_shape.py`: 47 unit tests covering the four
  reachable tail characters, every non-tail uppercase and
  lowercase letter, every digit tail, the `-`/`_`/padding
  rejections, the full alphabet matrix, the length boundary
  (0, 85, 86, 87, and 10,000), the input-type matrix
  (`None`, `bytes`, `int`, `float`, `bool`, `list`, `dict`,
  custom object), the no-amplification contract, the parity
  with a real Ed25519 signature, the 87-char / reachable-tail
  edge case (length check runs before tail check), and
  determinism.
- `scripts/technocore_cli.py`: new `sig-shape` subcommand that
  reads a candidate from `--value` or stdin (with one trailing
  newline stripped so piping a value works) and emits one JSON
  object on stdout with `valid`, `reason` (when invalid), and
  the contract `version`.
- `tests/test_cli.py`: 11 new subprocess tests covering the
  `sig-shape` subcommand, including the four reachable tail
  characters, length, tail, alphabet, empty, 87-char edge
  case, trailing-newline stripping, the one-line JSON
  contract, and parity with a real Ed25519 signature produced
  by the project's cryptographic module.
- `docs/sig-shape.md`: design notes for the validator,
  including the problem, audience, interface, security
  boundary, the four-reachable-tail math, the 87-character
  edge case, the no-amplification contract, the acceptance
  tests, the out-of-scope items, and the versioning rule.

### Security
- The validator is a pure function over its string input. It
  performs no network I/O, no subprocess, no URL resolution, no
  DNS lookup, no fetching, and no decoding. A pass proves only
  the surface canonical form, not the cryptographic validity of
  the signature or the identity of the signer.
- `SigShapeResult.reason` carries a static, parameter-free
  message. The validator never echoes the input value, the
  candidate string, or any fragment of it on any channel. The
  input is untrusted data and must not be amplified.
- The 87-character edge case is rejected on length **before**
  the tail check. A 65-byte tail can encode to a string whose
  last character is in `{A, Q, g, w}`, so a length-then-tail
  order is the only correct way to distinguish a 64-byte
  signature from a 65-byte tail.
- The validator does not run the sweep, scan for hazards,
  sign, POST, or otherwise transmit the input. Pair it with
  `technocore_verify` and `technocore_scanner` as needed.

## [0.8.0] — 2026-10-18

### Added
- `src/technocore_chunk.py`: public, reference implementation of a
  pure-Python message chunker that splits a string into pieces
  each no longer than `max_len` (default 4096, the documented
  per-message size cap). Pure function, stdlib-only, no network
  I/O, no subprocess, no decoding. Exposes:
  - `chunk_message(text, *, max_len=4096)` — returns a list of
    chunks, each no longer than `max_len` codepoints, with the
    round-trip property `"".join(chunks) == text`.
  - `DEFAULT_MAX_LEN` — the documented 4096-character cap.
  - `CHUNK_VERSION` — the integer version of the chunking
    contract, bumped whenever the public behavior changes.
  - `ChunkError` — raised for invalid arguments (non-`str`
    input, non-int `max_len`, `max_len` not a positive integer).
- `tests/test_chunk.py`: 40 unit tests covering identity, length
  contract, round-trip (ASCII, CJK, emoji, combining marks, NBSP,
  sweep codepoints, exact-boundary, one-past-boundary), split-
  point preference (whitespace boundary over hard cut, latest
  boundary, consecutive whitespace, oversize single token), the
  documented 4096-char cap, the custom-budget contract, sweep
  interaction, input validation, error-message hygiene, and
  determinism.
- `scripts/technocore_cli.py`: new `chunk` subcommand that reads
  text from `--file` or stdin and emits one JSON object on
  stdout with the chunk count, requested `max_len`, default
  `max_len`, contract `version`, and an ordered list of
  `{index, length, text}` chunks.
- `tests/test_cli.py`: 10 new subprocess tests covering the
  `chunk` subcommand, including default and custom `--max-len`,
  stdin / `--file` / `--file -` aliases, oversize tokens, exit
  codes for invalid `--max-len`, and the one-line JSON contract.
- `docs/chunking.md`: design notes for the chunker, including
  the problem, audience, interface, security boundary, design
  rules, acceptance tests, out-of-scope items, versioning, and
  worked examples.

### Security
- The chunker is a pure function over its string input. It
  performs no network I/O, no filesystem I/O beyond the input
  string, no subprocess execution, no URL resolution, no DNS
  lookup, no fetching, and no decoding of the input.
- `ChunkError` carries a static message that never echoes the
  input value. The chunker is a pure function over untrusted
  data and must not amplify the input onto any channel.
- A single oversize token (no whitespace anywhere in the input)
  is emitted as one chunk that may exceed `max_len`. The caller
  is responsible for detecting and handling oversize chunks; the
  chunker does not silently truncate, post, or error on them.
- The chunker does not run the sweep, scan for hazards, sign,
  POST, or otherwise transmit the input. Pair it with
  `technocore_sweep` and `technocore_scanner` as needed.

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
