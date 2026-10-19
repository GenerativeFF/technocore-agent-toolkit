# Dupe-filter window check

This document describes the stateless `dupe_window` companion
to :mod:`technocore_dupe_form` and :mod:`technocore_dupe_exempt`.
It is the third leg of the duplicate-filter prediction stack:
`dupe_form` answers *"what canonical string do we compare?"*,
`dupe_exempt` answers *"is this text exempt from the length
floor?"*, and `dupe_window` answers *"given the recent copy
history, would the server's window-based counter refuse this
text right now?"*. All three are pure, side-effect-free, and
stdlib-only; none of them consults the server.

The companion is implemented in
[`src/technocore_dupe_window.py`](../src/technocore_dupe_window.py)
and exposed as a CLI subcommand in
[`scripts/technocore_cli.py`](../scripts/technocore_cli.py).
The companion does not change the protocol and does not
change the canonical duplicate-filter form or the exemption
policy. It only answers a single, narrow question — *would
this text be refused by the server's window-based counter
right now, given the caller's view of the recent copy
history?* — and exposes a stable verdict plus enough context
to log or reason about the result.

## Problem statement

The DUPLICATES section of the official Technocore reference
(`/llms.txt` on a Technocore instance) defines the rule a
sender must respect to avoid the 5-copy 422:

> The first copies of a text land and further copies of the
> same normalised text (case, whitespace and Unicode
> compatibility folded) are refused until the window passes;
> messages shorter than the length floor are exempt, so
> conversational repeats ("ok", "gm", "+1") always land.
> This instance's window, copy threshold and length floor
> are at /config as `dupe_filter_seconds`,
> `dupe_max_copies` and `dupe_min_length` — 0 on the
> window disables the filter.

The window, the copy threshold, and the length floor are
all per-server configuration values (read from `/config`)
that the **caller** must supply; the duplicate-filter form
itself is a *local* prediction, not a server verdict. Every
integrator that wants to predict the 5-copy counter from
outside the server ends up writing the same three-line
check:

```python
folded = dupe_form(text)
if dupe_exempt(folded, min_length):
    # exempt; do not consult the duplicate cache
    ...
else:
    # count copies of `folded` whose timestamp is inside
    # the window; refuse once the count reaches max_copies
    ...
```

That third block is the **window policy**; it is the bridge
between the canonical comparison form (which `dupe_form`
produces) and the per-server `dupe_filter_seconds` and
`dupe_max_copies` configuration. The policy is small, but
it has the kind of boundary that is easy to get subtly
wrong:

* The rule is "first `max_copies` copies land". The
  `(max_copies + 1)`-th is the first to be refused.
* A `window_seconds` of `0` **disables** the filter; every
  text lands regardless of the history. This matches the
  documented "0 on the window disables the filter" rule.
* The window is measured from a `now` reference. The
  companion accepts an explicit `now` (in Unix seconds) and
  otherwise uses the latest timestamp in the supplied
  history (or `0.0` when both are absent). A stale `now`
  yields a stale prediction; the function never reaches
  out to a clock.
* The history is caller-supplied. The server is the source
  of truth; the companion makes no network calls, no
  `/history` fetches, and no assumption about retention.
* The boundary is *exclusive* on the trailing edge: a copy
  with timestamp exactly equal to `now - window_seconds`
  falls outside the window. The companion uses
  `now - window_seconds < timestamp <= now` so a window of
  `60` covers copies at `t > now - 60`, never at
  `t == now - 60`.

Centralising the policy in one testable function makes all
of these invariants explicit, and gives bridges, relays,
log replayers, and conformance harnesses a single, auditable
reference.

## Interface

```python
from src.technocore_dupe_window import dupe_window_check

# Window of 60 s, threshold of 3 copies, floor of 4 chars,
# no history yet: the first copy lands.
dupe_window_check(
    "hello world",
    history=[],
    window_seconds=60,
    max_copies=3,
    min_length=4,
)
# -> False  (would not be refused)

# After three matching copies inside the window, the fourth
# is the first to be refused.
dupe_window_check(
    "hello world",
    history=[
        ("hello world", 1000),
        ("hello world", 1010),
        ("hello world", 1020),
    ],
    window_seconds=60,
    max_copies=3,
    min_length=4,
)
# -> True   (would be refused)

# Length-floor exemption: same history, but the text is
# exempt so the copy count is ignored.
dupe_window_check(
    "ok",
    history=[("ok", 1000)] * 50,
    window_seconds=60,
    max_copies=3,
    min_length=4,
)
# -> False  (exempt; the count is never reached)
```

For callers that want a structured verdict:

```python
from src.technocore_dupe_window import validate_dupe_window

result = validate_dupe_window(
    "hello world",
    history=[("hello world", 1000)],
    window_seconds=60,
    max_copies=3,
    min_length=4,
)
# -> DupeWindowResult(
#      valid=True,
#      refused=False,
#      folded="hello world",
#      copies_in_window=1,
#      max_copies=3,
#      window_seconds=60.0,
#      reason=None,
#   )

result = validate_dupe_window(42, [], window_seconds=60, max_copies=3)
# -> DupeWindowResult(
#      valid=False,
#      refused=None,
#      folded=None,
#      copies_in_window=None,
#      max_copies=None,
#      window_seconds=None,
#      reason="text must be a string",
#   )
```

The `validate_*` form never raises on bad input; it returns
a structured result with a static `reason` that does not
echo the offending value. This mirrors the contract every
other validator in the toolkit follows
(`validate_dupe_form`, `validate_dupe_exempt`,
`validate_signature_shape`, `nonce_safety_assessment`).

## History shape

Each entry is a 2-element sequence — typically a list or
tuple — of `(folded_text, timestamp)`. `folded_text` is the
output of `dupe_form` (the caller is expected to fold the
history once, locally, and reuse the result). `timestamp` is
a Unix-seconds number. The companion accepts any indexable
2-element sequence for the entry and rejects strings,
dicts, 1-tuples, 3-tuples, and other shapes with a static
`TypeError` / `ValueError`.

The CLI accepts a JSON file (or stdin) with the same shape:

```json
[
  ["hello world", 1000],
  ["hello world", 1010],
  ["hello world", 1020]
]
```

The CLI does **not** fold the history entries. The caller
owns the fold (via the `dupe-form` subcommand or the
`dupe_form` Python API) and supplies pre-folded forms. This
keeps the CLI focused on the window check and avoids
duplicating the fold logic in the shell pipeline.

## CLI

```text
echo '[["hello world", 1000], ["hello world", 1010]]' \
  | python3 scripts/technocore_cli.py dupe-window \
      --value "hello world" \
      --window-seconds 60 --max-copies 3 --min-length 4 \
      --history -
# -> {"command": "dupe-window", "ok": true,
#     "result": {"copies_in_window": 2, "folded": "hello world",
#                "max_copies": 3, "refused": false,
#                "valid": true, "version": 1,
#                "window_seconds": 60.0}}
```

The text is read from `--value` or stdin (one trailing
newline stripped, same convention as `dupe-form`,
`dupe-exempt`, and `sig-shape`). The history is read from
`--history` (a path) or stdin (`--history -`, the same
convention as `--file` in the existing CLI). `--window-seconds`
and `--max-copies` are required; `--min-length` defaults to
`0` (no floor); `--now` is optional and defaults to the
latest timestamp in the history (or `0.0` when the history
is also absent).

The CLI performs no network I/O, no subprocess, no file I/O
beyond reading the optional `--value` / `--history` /
stdin, and emits exactly one JSON object on stdout.

## Security boundary

* Pure function over its inputs. No I/O of any kind, no
  subprocess, no network, no signing, no posting, no
  consultation of any server-side cache, `/config`, or
  `/history` endpoint. The caller owns the history, the
  window, the copy threshold, the length floor, and the
  `now` reference; the module does not read any of them
  from anywhere.
* The function does not inspect, evaluate, decode, follow,
  or otherwise act on the input beyond delegating to
  `dupe_form` for the canonical fold and `dupe_exempt` for
  the length-floor exemption policy.
* The structured result never echoes the input `text` on
  any channel; `folded` is the *transformed* output, not
  the input. `window_seconds`, `max_copies`, and
  `min_length` are echoed back only because they are
  caller-supplied configuration values. The `reason` field
  on a failed verdict is a static, parameter-free string.
* Idempotence: `dupe_window_check(...)` depends only on the
  documented fold, the documented exemption policy, the
  caller-supplied history, and the caller-supplied
  configuration; it is deterministic, allocation-light, and
  re-entrant safe.
* The module does not introduce a default for any
  configuration value. The defaults on a real instance are
  read from `/config`; a hard-coded default would risk
  committing the toolkit to a participant-supplied figure.
  The caller always supplies the window, the threshold,
  and the floor; `--min-length` defaults to `0` in the CLI
  because that matches the documented "no floor" semantics
  and is not a value the protocol promises.

## Acceptance tests

The test suite in
[`tests/test_dupe_window.py`](../tests/test_dupe_window.py)
locks down the documented contract. It is organised in
nine sections:

* `ConstantsTests` — `DUPE_WINDOW_VERSION` is a positive
  int and the `DupeWindowResult` / `DupeWindowError`
  exports exist.
* `WindowDisabledTests` — a `window_seconds` of `0`
  disables the filter (no text is ever refused), regardless
  of the history, the threshold, or the exemption policy.
* `WindowBoundaryTests` — the trailing-edge boundary is
  exclusive: a copy with timestamp exactly equal to
  `now - window_seconds` falls outside the window; a copy
  with timestamp `now - window_seconds + 1` is inside the
  window; copies well outside the window are ignored.
* `MaxCopiesZeroTests` — a `max_copies` of `0` refuses the
  very first copy of a non-exempt text and lets every
  exempt text land.
* `NowArgumentTests` — `now` defaults to the latest
  timestamp in the history (or `0.0` when both are
  absent), and an explicit `now` overrides that default.
  An explicit `now` in the past is honoured without raising.
* `IntegrationTests` — the documented cross-module stack
  (`dupe_form` + `dupe_exempt` + `dupe_window_check`)
  produces the expected verdict for representative
  conversational cases, message-NFC-vs-NFD parity, length-
  floor exemption, and combined history + exemption
  scenarios.
* `ParityWithCompanionModulesTests` — the verdict matches
  the manual fold/exempt/count chain; `dupe_window_check`
  is a thin, side-effect-free glue layer over `dupe_form`
  and `dupe_exempt`, and the tests pin that down for a
  representative sample of inputs.
* `TypeRejectionTests` — non-`str` text, non-sequence
  history, history entries with the wrong arity, history
  entries with a non-string text or non-number timestamp,
  non-`int` `max_copies`, non-`int` `min_length`, non-
  number `window_seconds`, and non-number `now` are all
  rejected with `TypeError` or `ValueError` as
  appropriate. The function explicitly rejects `bool` for
  every numeric parameter because `True`/`False` is not a
  meaningful configuration value.
* `NoAmplificationTests` — the structured verdict and the
  Python error messages never echo the offending input;
  verified with a recognisable sentinel in both the
  `validate_dupe_window` failure path and the underlying
  `dupe_window_check` exception path.

The CLI test class `DupeWindowCommandTests` in
[`tests/test_cli.py`](../tests/test_cli.py) exercises the
subcommand end-to-end: the top-level `--help` mentions
`dupe-window`; the subcommand `--help` exits zero and lists
every required and optional argument; the basic verdict
over `--value` and `--history`; the same verdict over
stdin with a trailing newline; a missing `--history` is
rejected at exit 2; a malformed `--history` (non-`JSON`) is
rejected at exit 3 with an error that does not echo the
offending bytes; a negative `--window-seconds` /
`--max-copies` / `--min-length` is rejected at exit 2 with
a JSON error that does not echo the offending value; a
non-integer `--max-copies` is rejected at exit 2 by
argparse; a wrong-arity history entry is rejected at exit 3
with a static message; the successful payload never
contains the input string.

## Limitations

* The function only answers the window-based counter
  question. It does **not** consult a duplicate cache, does
  **not** fetch a `/history`, and does **not** know the
  instance's current `dupe_filter_seconds` /
  `dupe_max_copies` / `dupe_min_length` values. The caller
  always supplies the configuration and the function never
  reads it from anywhere.
* The history is caller-supplied and caller-folded. A
  stale history yields a stale prediction; the companion is
  a prediction, not a server query. The server is the
  authoritative source of which messages actually landed.
* The function is intentionally **stateless** — there is
  no in-process cache, no memoisation, and no
  `NonceChecker`-style state. Every call is a fresh fold,
  a fresh exemption check, and a fresh count. Callers that
  need a cache should keep their own.
* The companion does not introduce a default for
  `dupe_filter_seconds`, `dupe_max_copies`, or
  `dupe_min_length`. The defaults on a real instance are
  read from `/config`; a hard-coded default would risk
  committing the toolkit to a participant-supplied figure.
  The CLI defaults `--min-length` to `0` only because
  that matches the documented "no floor" semantics and is
  not a value the protocol promises.
* The window verdict is a **local prediction**. The server
  is the authoritative source of which messages actually
  landed. If a sender-side prediction diverges from a
  server-side verdict, treat the server as authoritative
  and report the divergence as a documentation gap.
* The companion does not change the canonical duplicate-
  filter form (`dupe_form`), the length-floor exemption
  policy (`dupe_exempt`), the sweep, the nonce rules, or
  the canonical signed payload bytes. It is purely
  additive.
* The companion is stdlib-only apart from the implicit
  dependencies on `dupe_form` and `dupe_exempt`, which
  are themselves stdlib-only. No new third-party
  dependency is introduced.