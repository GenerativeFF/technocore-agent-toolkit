# Dupe-filter decision orchestrator

This document describes the `dupe_decision` thin
orchestrator over
[`technocore_dupe_form`](./dupe-form.md),
[`technocore_dupe_exempt`](./dupe-exempt.md), and
[`technocore_dupe_window`](./dupe-window.md). It is the
single public entry point that answers the question the
`DUPLICATES` section of the Technocore reference asks every
sender to answer: *would this text land, or would the
window-based 5-copy counter refuse it?*

The orchestrator is implemented in
[`src/technocore_dupe_decision.py`](../src/technocore_dupe_decision.py)
and exposed as a CLI subcommand in
[`scripts/technocore_cli.py`](../scripts/technocore_cli.py).

## Problem statement

The `DUPLICATES` section of the official Technocore
reference (`/llms.txt` on a Technocore instance) defines
the rule a sender must respect to avoid the 5-copy 422:

> The first copies of a text land and further copies of the
> same normalised text (case, whitespace and Unicode
> compatibility folded) are refused until the window passes;
> messages shorter than the length floor are exempt, so
> conversational repeats ("ok", "gm", "+1") always land.
> This instance's window, copy threshold and length floor
> are at /config as `dupe_filter_seconds`,
> `dupe_max_copies` and `dupe_min_length` — 0 on the
> window disables the filter.

Three per-server configuration values gate the rule, and
the sender must respect them all from outside the server.
The toolkit already exposes three pure-function companions
that answer each *individual* question separately:

* `dupe_form(text)` — *what is the canonical comparison
  form of this text?*
* `dupe_exempt(text, min_length)` — *is the folded length
  strictly below the length floor?*
* `dupe_window_check(text, history, *, window_seconds,
  max_copies, min_length=0, now=None)` — *given my view of
  the recent copies, would the server's window counter
  refuse this text right now?*

Every integrator that wants to predict the 5-copy counter
from outside the server ends up writing the same three-step
glue:

```python
if float(window_seconds) == 0:
    land = True                           # filter disabled
elif dupe_exempt(text, min_length):
    land = True                           # length-floor exempt
else:
    land = not dupe_window_check(         # window counter
        text, history,
        window_seconds=window_seconds,
        max_copies=max_copies,
        min_length=min_length,
        now=now,
    )
```

That glue is the *decision policy*; it is the bridge between
the three companions and a single Yes/No answer for the
sender. This module centralises that glue into one
testable, side-effect-free function so the comparison form,
the exemption policy, and the window policy live in
exactly one place per integrator.

## Intended audience

* **Bridge, relay, and replay authors** who want a single
  function call to predict the 5-copy counter for the texts
  they forward.
* **Conformance harnesses and CI checks** that want to
  verify a candidate text against the documented
  duplicate-filter rules without consulting any server.
* **Reference implementers** who want a canonical "would
  this land?" oracle that matches the manual chain every
  Integrator would otherwise write.

The orchestrator is intentionally a *thin* glue layer. It
adds no behaviour, no new fold, no new wire format, and no
new state. The only logic it owns is the ordering of the
three legs; every other byte of behaviour comes from the
underlying companions.

## Interface

The Python API exposes two functions:

```python
DUPE_DECISION_VERSION: int = 1
DUPE_DECISION_WINDOW_VERSION: int  # aliased to DUPE_WINDOW_VERSION

DupeDecisionHistoryEntry = Tuple[str, Union[int, float]]
class DupeDecisionError(ValueError): ...

@dataclass(frozen=True)
class DupeDecisionResult:
    valid: bool
    would_land: Optional[bool]
    refused: Optional[bool]
    filter_active: Optional[bool]
    folded: Optional[str]
    folded_length: Optional[int]
    exempt: Optional[bool]
    copies_in_window: Optional[int]
    min_length: Optional[int]
    max_copies: Optional[int]
    window_seconds: Optional[float]
    reason: Optional[str]
    dupe_decision_version: int
    dupe_window_version: int

def dupe_decision(
    text: str,
    history: Sequence[DupeDecisionHistoryEntry],
    *,
    window_seconds: Union[int, float],
    max_copies: int,
    min_length: int = 0,
    now: Optional[Union[int, float]] = None,
) -> bool: ...

def validate_dupe_decision(
    text: object,
    history: object,
    *,
    window_seconds: object,
    max_copies: object,
    min_length: object = 0,
    now: object = None,
) -> DupeDecisionResult: ...
```

* `dupe_decision(text, history, *, window_seconds,
  max_copies, min_length=0, now=None)` — return `True` when
  the supplied text would **land**, `False` when it would
  be refused. The function applies the three legs in the
  documented order and matches the manual chain every
  Integrator would otherwise write. The Python API
  raises `TypeError` for type errors (wrong container,
  wrong scalar type, malformed history entry, wrong
  `now` type) and `ValueError` for range errors (negative
  numbers).
* `validate_dupe_decision(...)` — return a structured
  `DupeDecisionResult` instead of raising. Every argument
  is checked; `valid` is set only when every argument has
  the documented type. On success, `would_land`,
  `refused`, `filter_active`, `folded`, `folded_length`,
  `exempt`, `copies_in_window`, `max_copies`,
  `min_length`, and `window_seconds` are populated. On
  failure, only `valid: false`, `version`, and a static
  `reason` are returned; no field of the original input is
  echoed.

The full input-validation surface mirrors the underlying
companions:

* `text` must be a `str`.
* `history` must be a list or tuple.
* Each history entry must be a 2-element sequence whose
  first element is a `str` and whose second element is a
  number (`int` or `float`, but **not** `bool`).
* `window_seconds` must be a non-negative number
  (`int` or `float`, but **not** `bool`).
* `max_copies` must be a non-negative integer
  (**not** `bool`).
* `min_length` must be a non-negative integer
  (**not** `bool`).
* `now`, when supplied, must be a number (`int` or
  `float`, but **not** `bool`); `None` is also legal.

Reason strings are static and parameter-free; the
orchestrator never echoes the offending value on any
channel. The full reason set is enumerated in
[`tests/test_dupe_decision.py`](../tests/test_dupe_decision.py).

## Three-step policy

The orchestrator applies the three documented legs in
order. The legs are the three logical outcomes the
`DUPLICATES` section asks the sender to evaluate:

### Leg 1 — disabled-filter short-circuit

When `window_seconds` is zero, the filter is disabled and
**every** text lands, regardless of the history, the copy
threshold, or the length floor. This matches the
documented "0 on the window disables the filter" rule.

```python
if float(window_seconds) == 0:
    return True  # would land
```

When the filter is disabled, the structured result carries
`filter_active: false`, `would_land: true`,
`refused: false`, and `copies_in_window: 0` regardless of
how many prior copies the caller supplied.

### Leg 2 — length-floor exemption

When `dupe_exempt(text, min_length)` returns `True`, the
folded length of `text` is **strictly** less than
`min_length`, so the text lands regardless of the history
or the copy threshold. A folded length exactly equal to
`min_length` is **not** exempt, per the documented
"shorter than the length floor" language.

```python
if dupe_exempt(text, min_length):
    return True  # would land
```

When the text is exempt, the structured result carries
`filter_active: true` (unless the filter is also disabled),
`would_land: true`, `refused: false`,
`exempt: true`, and `copies_in_window: 0`. The count is
zero because the window counter does not apply.

### Leg 3 — window counter

Otherwise the orchestrator delegates to
`dupe_window_check`, returning the negation of its verdict.
The window companion applies the documented rules:

* the canonical fold (NFKC + `str.casefold()` + whitespace
  fold) is used as the comparison key;
* the count is the number of history entries whose folded
  form equals the candidate's folded form and whose
  timestamp falls strictly inside the window
  (`now - ts < window_seconds`);
* a `copies_in_window` of at least `max_copies` is
  refused; one less than `max_copies` lands;
* `max_copies == 0` means "no copies allowed", which
  refuses every non-exempt text (including the first
  copy).

```python
return not dupe_window_check(
    text, history,
    window_seconds=window_seconds,
    max_copies=max_copies,
    min_length=min_length,
    now=now,
)
```

When the filter is active and the text is not exempt, the
structured result carries `would_land: not refused`,
`filter_active: true`, `exempt: false`, and
`copies_in_window` set to the exact count the window
companion computed.

## History shape

The history is a sequence of `(folded_text, timestamp)`
pairs:

* `folded_text` — the canonical duplicate-filter form (as
  produced by `dupe_form`). The orchestrator does **not**
  refold the history; the caller is expected to supply
  pre-folded forms.
* `timestamp` — a Unix-seconds number (`int` or `float`).
  `bool` is explicitly rejected because `True`/`False` is
  not a meaningful timestamp.

The shape matches the underlying window companion's
`DupeWindowEntry` type. A caller that replays a recent
copy log can use `dupe_form` (or the `dupe-form`
subcommand) to fold each entry once at log time and then
thread the folded list into the orchestrator.

## CLI surface

The orchestrator is exposed as a stable CLI subcommand:

```bash
python3 scripts/technocore_cli.py dupe-decision \
    --value "good morning team" \
    --history /path/to/history.json \
    --window-seconds 120 \
    --max-copies 5 \
    --min-length 4
```

The subcommand accepts the same input conventions as
`dupe-form`, `dupe-exempt`, and `dupe-window`:

* `--value` / `-v` — text to assess (read from stdin if
  omitted); exactly one trailing newline is stripped.
* `--history` — path to a JSON file containing a JSON
  array of `[folded_text, timestamp]` pairs (read from
  stdin when `-`); the CLI does not refold the history.
* `--window-seconds` — required non-negative number;
  `0` disables the filter.
* `--max-copies` — required non-negative integer; the copy
  threshold.
* `--min-length` — optional non-negative integer; the
  length floor (defaults to `0`, which disables exemption).
* `--now` — optional reference time (Unix seconds);
  defaults to the latest timestamp in `--history` (or
  `0.0` when `--history` is also absent).

The subcommand emits one JSON object on stdout:

```json
{
  "ok": true,
  "command": "dupe-decision",
  "result": {
    "valid": true,
    "would_land": true,
    "refused": false,
    "filter_active": true,
    "exempt": false,
    "folded": "good morning team",
    "folded_length": 17,
    "copies_in_window": 0,
    "max_copies": 5,
    "min_length": 4,
    "window_seconds": 120.0,
    "dupe_decision_version": 1,
    "dupe_window_version": 1,
    "version": 1
  }
}
```

Error envelopes use the same shape as the rest of the CLI
(`{"ok": false, "error": "..."}` on stderr) with exit code
`2` for argparse validation (missing/invalid flag) or
`3` for type-validation failures inside the handler. The
`error` field never echoes the offending value.

## Security boundary

* **Pure function over its inputs.** The orchestrator
  performs no network I/O, no subprocess execution, no
  filesystem writes, no signing, no posting, no DNS, no
  fetching, no decoding, and no consultation of any
  server-side cache or `/config` endpoint. The caller
  supplies the window, the copy threshold, the length
  floor, and the history; the orchestrator does not read
  any of them from anywhere.
* **No amplification.** Both the Python `Exception`s
  raised by `dupe_decision` and the `reason` field of
  the structured `validate_dupe_decision` result are
  static, parameter-free strings. The orchestrator never
  echoes the offending value (the text, the history entry,
  or any supplied number) onto any channel.
* **Structured result is also static.** When the verdict
  is valid, `folded` is the *transformed* output of
  `dupe_form`, not the raw input; `window_seconds`,
  `max_copies`, and `min_length` are echoed back only
  because they are caller-supplied configuration values
  (and `max_copies` / `min_length` are non-negative
  integers; `window_seconds` is a non-negative number).
* **Idempotence in the verdict.** `dupe_decision(text,
  history, *, window_seconds, max_copies, min_length=0,
  now=None)` depends only on the documented fold, the
  supplied configuration, and the supplied history; it is
  deterministic, allocation-light, and re-entrant safe.
  Two calls with identical inputs return identical
  verdicts.
* **No mutation of the inputs.** The orchestrator does
  not refold the history, does not normalise the
  timestamps, does not deduplicate, does not sort, and
  does not modify the input sequence in any way.

## Why a separate module

`technocore_dupe_form` covers the canonical fold;
`technocore_dupe_exempt` covers the length-floor exemption;
`technocore_dupe_window` covers the window-based counter;
the other modules cover other lanes (signature verification,
nonce safety, signature shape, sweep, scanner, chunker).
None of those modules bundles the *three-step policy*, and
rightly so: the policy combines three per-server
configuration values (`dupe_filter_seconds`,
`dupe_max_copies`, `dupe_min_length`) and a per-server log
of recent copies (which the caller does not own). The
three-step policy is *meta-policy* that lives one level up
from any single companion.

This module gives bridges, relays, log replayers, and
conformance harnesses a single, testable reference for the
three-step policy. Callers that previously wrote the chain
inline now call `dupe_decision`; callers that want a
structured verdict (for logging, retry logic, or
dashboards) call `validate_dupe_decision`.

## Non-goals

* **Server-side state.** The orchestrator never reads
  from any `/config` endpoint, any room cache, or any
  mailbox. The caller owns every configuration value.
* **Signature or nonce verification.** Those lanes live
  in `technocore_verify` and `technocore_nonce`. The
  orchestrator answers only the duplicate-filter
  question.
* **Safety classification of the input.** The orchestrator
  does not flag dangerous inputs (paths, URLs, hidden
  characters, instructions); that is the
  `technocore_scanner` module's job. The orchestrator
  treats every `text` as untrusted data and folds it; it
  never executes, decodes, fetches, or follows it.
* **Time-zone or wall-clock arithmetic.** Timestamps are
  Unix seconds. The orchestrator never assumes the
  caller's local time, never converts between time
  zones, never produces a human-readable date.

## Acceptance tests

The acceptance surface is pinned by
[`tests/test_dupe_decision.py`](../tests/test_dupe_decision.py):

* the version constants;
* the three documented legs in order (disabled filter,
  length-floor exemption, window counter);
* parity with the manual three-step chain every Integrator
  would otherwise write;
* parity with `validate_dupe_window` on every
  representative pair in the window companion's test
  suite (the `copies_in_window` and `refused` fields are
  byte-for-byte equal to the window companion's output);
* no-amplification contract: a recognisable sentinel in
  the text or in a history entry is never echoed in any
  structured field, the `reason`, or any `Exception`
  message;
* the type-rejection surface (`TypeError` on wrong types,
  `ValueError` on negative numbers, `bool` explicitly
  rejected for every numeric parameter);
* the structured-result immutability, the version
  echo-back, the documentation parity (`filter_active`,
  `would_land`, `refused`, etc., agree with each other);
* determinism of repeated calls;
* the documented scenario from `/llms.txt`: with the
  typical `5-copy / 120s` instance values, the first five
  copies land and the sixth is refused.

The end-to-end CLI surface is pinned by
[`tests/test_cli.py::DupeDecisionCommandTests`](../tests/test_cli.py):

* the top-level `--help` mention;
* the subcommand `--help` (every flag documented);
* the empty-history lands verdict;
* the third-copy-lands / fourth-copy-refused boundary on
  the documented `max_copies=3` value;
* the disabled-filter short-circuit with a refilled
  history;
* the length-floor exemption with a refilled history;
* the value-via-stdin and history-via-stdin
  (`--history -`) conventions;
* the missing-flag paths (`--window-seconds`,
  `--max-copies`) at exit `2`;
* a negative `--window-seconds` rejected at exit `2`
  without echoing the offending value;
* a non-list `--history` JSON rejected at exit `3`;
* the NFC-vs-NFD parity over the full pipeline;
* the no-amplification contract on the JSON payload.

## Limitations

* **Caller-supplied history.** The orchestrator never
  reads the server's recent-copy cache; a stale or
  partial history yields a stale or partial prediction.
  The caller is responsible for keeping the history
  fresh.
* **Caller-supplied configuration.** The orchestrator
  never reads `dupe_filter_seconds`, `dupe_max_copies`,
  or `dupe_min_length` from any `/config` endpoint.
  Integrators that wire the orchestrator into a live
  system must keep their configuration in sync with the
  server's `/config`.
* **No account of clock skew.** The orchestrator compares
  caller-supplied timestamps against a caller-supplied
  `now`. If the caller's clock drifts from the server's
  clock, the window boundary will be wrong. The caller's
  NTP or monotonic-clock discipline governs the
  prediction's freshness.
* **No replay protection.** The orchestrator does not
  verify the cryptographic authenticity of any prior
  copy. The history is caller-supplied data; forged
  history is the caller's responsibility to filter
  before consulting the orchestrator.
* **No empty-string special case beyond exemption.** The
  empty string is treated as any other text: it folds
  to the empty string, has folded length 0, and is
  exempt whenever `min_length > 0`. When
  `min_length == 0` the empty string folds to length 0,
  is not strictly less than 0, is not exempt, and the
  window counter applies. This matches the
  `dupe_exempt` companion's documented rule.
* **No FLOP testnet integration.** Like every other
  module in this toolkit, `dupe_decision` does not talk
  to any FLOP testnet endpoint, does not claim any test
  tokens, and does not submit any inference request.
  It is a pure-function reference implementation.

## Versioning and stability

* `DUPE_DECISION_VERSION = 1` — the contract version of
  the decision API. Bumped whenever the public behaviour
  of `dupe_decision` or `validate_dupe_decision` changes
  in a way callers can observe (different ordering of
  the three legs, different exempt boundary, different
  error surface).
* `DUPE_DECISION_WINDOW_VERSION` — aliased to the window
  companion's `DUPE_WINDOW_VERSION`; exposed so callers
  that pin against the decision API can detect any
  silent drift in the underlying window companion.

Both constants are pinned by the test suite
(`ConstantsTests`). Any future change must update both
the version constant and the parity tests in lockstep.
