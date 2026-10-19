# Dupe-filter exemption check

This document describes the stateless `dupe_exempt` companion
to :mod:`technocore_dupe_form`. It is a small policy layer
that captures a per-server configuration decision the
duplicate-filter requires every integrator to make, and
turns it into a single, testable, side-effect-free function.

The companion is implemented in
[`src/technocore_dupe_exempt.py`](../src/technocore_dupe_exempt.py)
and exposed as a CLI subcommand in
[`scripts/technocore_cli.py`](../scripts/technocore_cli.py).
The companion does not change the protocol and does not
change the canonical duplicate-filter form. It only answers
a single, narrow question — *would this text be exempt from
the length floor on a server whose `dupe_min_length` is the
supplied value?* — and exposes a stable verdict plus enough
context to log or reason about the result.

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

The length floor is a per-server configuration value (read
from `/config`) that the **caller** must supply; the
duplicate-filter form itself is a *local* prediction, not a
server verdict. Every integrator that wants to predict the
5-copy counter from outside the server ends up writing the
same two-line policy check:

```python
folded = dupe_form(text)
if len(folded) < min_length:
    # exempt; do not consult the duplicate cache
    ...
else:
    # check the duplicate cache for `folded`
    ...
```

That two-line check is the **exemption policy**; it is the
bridge between the canonical comparison form (which the
`dupe-form` module produces) and the per-server `dupe_min_length`
configuration. The policy is small, but it has the kind of
boundary that is easy to get subtly wrong:

* The rule is "shorter than the length floor", not "shorter
  than or equal to". A folded length of exactly `min_length`
  is **not** exempt.
* The comparison is on the *folded* length, not the raw
  input length. A 12-character input full of leading and
  trailing spaces can fold to a 2-character form and is
  therefore exempt.
* The comparison is on the *folded* length, not the *raw
  byte* length. CJK, emoji, and combining sequences can
  fold to a different number of codepoints.
* The floor is per-server config, not a protocol constant.
  A companion that hard-codes a default risks committing to
  a participant-supplied figure.

Centralising the policy in one testable function makes all
four of these invariants explicit, and gives bridges, relays,
log replayers, and conformance harnesses a single, auditable
reference.

## Interface

```python
from src.technocore_dupe_exempt import dupe_exempt

dupe_exempt("ok", 3)         # -> True   (folded length 2 < 3)
dupe_exempt("ok", 2)         # -> False  (folded length 2 not < 2)
dupe_exempt("hello world", 3) # -> False  (folded length 11 not < 3)
dupe_exempt("", 0)           # -> False  (0 not < 0)
dupe_exempt("", 1)           # -> True   (0 < 1)
dupe_exempt("ok", 0)         # -> False  (2 not < 0)
```

For callers that want a structured verdict:

```python
from src.technocore_dupe_exempt import validate_dupe_exempt

result = validate_dupe_exempt("ok", 3)
# -> DupeExemptResult(
#      valid=True,
#      exempt=True,
#      folded="ok",
#      folded_length=2,
#      min_length=3,
#      reason=None,
#   )

result = validate_dupe_exempt(42, 3)  # any non-str input
# -> DupeExemptResult(
#      valid=False,
#      exempt=None,
#      folded=None,
#      folded_length=None,
#      min_length=None,
#      reason="text must be a string",
#   )
```

The `validate_*` form never raises on bad input; it returns
a structured result with a static `reason` that does not
echo the offending value. This mirrors the contract every
other validator in the toolkit follows
(`validate_dupe_form`, `validate_signature_shape`,
`nonce_safety_assessment`).

## CLI

```text
python3 scripts/technocore_cli.py dupe-exempt \
    --value "ok" --min-length 3
# -> {"command": "dupe-exempt", "ok": true,
#     "result": {"exempt": true, "folded": "ok",
#                "folded_length": 2, "min_length": 3,
#                "valid": true, "version": 1}}
```

The text is read from `--value` or stdin (one trailing
newline stripped, same convention as `dupe-form` and
`sig-shape`). `--min-length` is a required non-negative
integer; the caller owns the value. The CLI performs no
network I/O, no subprocess, no file I/O beyond reading the
optional `--value` / stdin, and emits exactly one JSON
object on stdout.

## Security boundary

* Pure function over its inputs. No I/O of any kind, no
  subprocess, no network, no signing, no posting, no
  consultation of any server-side cache or `/config`
  endpoint.
* The function does not inspect, evaluate, decode, follow,
  or otherwise act on the input beyond delegating to
  `dupe_form` for the canonical fold.
* The structured result never echoes the input `text` on
  any channel; `min_length` is echoed back only because it
  is a non-negative integer the caller supplied. The
  `reason` field on a failed verdict is a static,
  parameter-free string.
* Idempotence: `dupe_exempt(text, n)` depends only on the
  documented fold and the supplied floor; it is
  deterministic, allocation-light, and re-entrant safe.
* The module does not enforce the documented window
  (`dupe_filter_seconds`) or the copy threshold
  (`dupe_max_copies`). It answers one question — *would
  this text be exempt from the length floor?* — and does
  not consult the server's cache or remember prior
  decisions.

## Acceptance tests

The test suite in
[`tests/test_dupe_exempt.py`](../tests/test_dupe_exempt.py)
locks down the documented contract. It is organised in
eight sections:

* `ConstantsTests` — `DUPE_EXEMPT_VERSION` is a positive
  int.
* `BoundaryTests` — the rule is **strict** less-than: a
  folded length equal to the floor is NOT exempt; a folded
  length of zero is exempt at every positive floor and
  not exempt at floor zero; `min_length=0` disables
  exemption for every non-empty text.
* `ConversationalRepeatTests` — the three documented
  conversational repeats (`ok`, `gm`, `+1`) all fold to a
  two-codepoint form and are therefore exempt at every
  realistic floor (3, 5, 8, 10, 20) and **not** exempt at
  floor 2.
* `WhitespaceBypassTests` — adding leading, trailing, or
  internal whitespace does not change the exemption at
  any non-negative floor; the whitespace fold collapses
  to a single ASCII space and the ends are stripped.
* `CaseFoldingBypassTests` — case-folding does not let
  the same text bypass the floor; "OK" folds to "ok"
  (length 2), and "Straße" casefolds to "strasse"
  (length 7), which is NOT exempt at floor 7 and IS
  exempt at floor 8.
* `TypeRejectionTests` — non-`str` `text`, non-`int`
  `min_length`, `bool` `min_length`, and negative
  `min_length` are all rejected with `TypeError` or
  `ValueError` as appropriate. The function explicitly
  rejects `bool` because `True`/`False` is not a
  meaningful length floor.
* `ParityWithDupeFormTests` — the verdict equals
  `len(dupe_form(text)) < min_length` for every
  representative pair; the function is deterministic and
  idempotent.
* `ValidateDupeExemptTests` — the structured result
  carries the verdict, the fold, the folded length, the
  min length, and a static reason; the result never
  echoes the input value (verified with a recognisable
  sentinel) and the result dataclass is immutable.

The CLI test class `DupeExemptCommandTests` in
[`tests/test_cli.py`](../tests/test_cli.py) exercises the
subcommand end-to-end: the top-level `--help` mentions
`dupe-exempt`; the subcommand `--help` exits zero and
lists `--value` and `--min-length`; the basic verdict
over `--value`; the same verdict over stdin with a
trailing newline; NFC vs NFD parity; `--min-length` is
required; a negative `--min-length` is rejected at exit 2
with a JSON error that does not echo the offending value;
a non-integer `--min-length` is rejected at exit 2 by
argparse; the successful payload never contains the input
string.

## Limitations

* The function only answers the length-floor exemption
  question. It does **not** consult a duplicate cache,
  does **not** track prior decisions, and does **not**
  know the window (`dupe_filter_seconds`) or the copy
  threshold (`dupe_max_copies`). Those are the caller's
  responsibility.
* The function is intentionally **stateless** — there is
  no in-process cache, no memoisation, and no
  `NonceChecker`-style state. Every call is a fresh fold
  and a fresh length comparison. This keeps the surface
  small and the contract testable; callers that need a
  cache should keep their own.
* The companion does not introduce a default for
  `dupe_min_length`. The default on a real instance is
  read from `/config`; a hard-coded default would risk
  committing the toolkit to a participant-supplied
  figure. The caller always supplies the floor.
* The exemption verdict is a **local prediction**. The
  server is the authoritative source of which messages
  actually landed. If a sender-side prediction diverges
  from a server-side verdict, treat the server as
  authoritative and report the divergence as a
  documentation gap.
* The companion does not change the canonical duplicate
  filter form (`dupe_form`) and does not change the
  sweep, the nonce rules, or the canonical signed
  payload bytes. It is purely additive.
* The companion is stdlib-only apart from the implicit
  dependency on `dupe_form`, which is itself stdlib-only.
  No new third-party dependency is introduced.
