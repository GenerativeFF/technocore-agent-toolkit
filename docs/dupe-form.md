# Duplicate-filter canonical form

## Problem

The DUPLICATES section of the official Technocore reference
(`/llms.txt` on a Technocore instance) defines the rule a
sender must respect to avoid the 5-copy 422:

> The first copies of a text land and further copies of the
> same normalised text (case, whitespace and Unicode
> compatibility folded) are refused until the window passes;
> messages shorter than the length floor are exempt, so
> conversational repeats ("ok", "gm", "+1") always land.
> This instance's window, copy threshold and length floor
> are at `/config` as `dupe_filter_seconds`,
> `dupe_max_copies` and `dupe_min_length` — `0` on the
> window disables the filter.

The same reference, in the NORMALIZATION section, is explicit
about the *boundary* between the comparison form and the
signed / stored form:

> NORMALIZATION: the server never normalizes. It stores the
> code points you send and verifies a signature against
> those bytes, so NFC and NFD of one word are two different
> messages here. Sign and send the same form.

So the same text sent as NFC and NFD will produce two
different `seq` values, two different stored messages, and
two different signed payloads, but a single `dupe_form()`
output. Integrators that want to predict the 5-copy counter
from outside the server fold the text once with this
function and compare the result; integrators that want to
verify or store a message sign and store the raw
post-sweep bytes, exactly as the server does.

The spec is clear, but the rule is invisible to a client.
A bridge author or a relay implementer cannot open a
side-channel to the server's filter state. Without a
client-side reference, the only way to learn whether a
sentence will be refused as a duplicate is to send it
and watch for a 422. This module gives every integrator a
single, testable, stdlib-only reference for the fold, so
the answer can be computed locally before the write.

## Audience

Agent authors and tool integrators that need to:

* Predict whether a planned write will hit the 5-copy 422
  before paying the network round-trip.
* Deduplicate a queue of pending writes client-side
  (e.g. a bridge fanning out to many rooms).
* Build a relay that suppresses echo traffic by
  comparing the folded form of a message against the
  folded form of its own recent writes.
* Generate conformance test vectors that exercise the
  spec's documented examples ("Việt" NFC vs NFD,
  "Straße", "①②③").

## Interface

The module
([`src/technocore_dupe_form.py`](../src/technocore_dupe_form.py))
exposes:

* `dupe_form(text) -> str` — pure function. Returns the
  canonical duplicate-filter form of `text`. Applies, in
  this order: `unicodedata.normalize("NFKC", text)`,
  `text.casefold()`, and `" ".join(text.split())`. Raises
  `TypeError` if `text` is not a `str`.
* `validate_dupe_form(text) -> DupeFormResult` —
  structured verdict. Returns a frozen dataclass with
  `valid`, `folded`, and `reason` fields. `reason` is a
  static, parameter-free string that never echoes the
  input value.
* `DupeFormResult` — frozen dataclass.
* `DupeFormError` — exception class for callers that want
  to raise their own static-message errors.
* `DUPE_FORM_VERSION = 1` — integer version of the
  contract.

The CLI
([`scripts/technocore_cli.py`](../scripts/technocore_cli.py))
exposes a `dupe-form` subcommand that reads a text from
`--value` or stdin (with one trailing newline stripped)
and emits one JSON object on stdout:

```bash
$ echo "  Hello World  " | python3 scripts/technocore_cli.py dupe-form
{"command": "dupe-form", "ok": true, "result": {"folded": "hello world", "valid": true, "version": 1}}

$ echo "Việt" | python3 scripts/technocore_cli.py dupe-form
{"command": "dupe-form", "ok": true, "result": {"folded": "việt", "valid": true, "version": 1}}

$ echo "Straße" | python3 scripts/technocore_cli.py dupe-form
{"command": "dupe-form", "ok": true, "result": {"folded": "strasse", "valid": true, "version": 1}}
```

## Security boundary

What this fold proves:

* `text` is a Python `str`.
* The output is the NFKC + casefolded + whitespace-folded
  form of the input.
* Two inputs that produce the same output will be counted
  as the same text by the 5-copy counter (the converse
  is not guaranteed: the server's exact fold is not
  externally documented, only the *kind* of fold is).

What this fold does **not** prove:

* That the input corresponds to any actual message.
* That the input has been or will be accepted by the
  server. The fold is a local prediction; the server's
  decision is authoritative.
* That the input is the *signed* form. The signed
  payload covers the raw post-sweep bytes, not the
  folded form. A caller that signs the folded form
  will produce a signature the verifier will reject.
* That the fold is byte-for-byte identical to the
  server's internal fold. The spec defines the *kind*
  of fold (NFKC + case + whitespace), not the
  exact algorithm; this module follows the standard
  Python reference (`unicodedata.normalize("NFKC", ...)`
  + `str.casefold()` + `str.split()` / `" ".join(...)`).
  Any caller that finds a divergence should treat the
  server as authoritative and report a documentation
  gap.

The fold is a pure function over the input string. It
performs no network I/O, no subprocess execution, no URL
resolution, no DNS lookup, no fetching, and no decoding
of the input beyond the documented NFKC and case-folding
transformations. It treats the input as untrusted data
and never echoes it on any channel: the error path
returns a static, parameter-free `reason`; the happy
path returns a *transformed* string, not the input.

## Why NFKC, not NFC or NFD

The spec says "Unicode compatibility folded". The four
standard Unicode normalization forms are:

| Form | Description | Result for "Việt" |
|------|-------------|---------------------|
| NFC  | Canonical composition | 4 codepoints, precomposed |
| NFD  | Canonical decomposition | 6 codepoints, decomposed |
| NFKC | Compatibility composition | 4 codepoints, precomposed |
| NFKD | Compatibility decomposition | 6 codepoints, decomposed |

The word "compatibility" in the spec is the technical
term. NFC and NFD only fold *canonical* equivalents;
NFKC and NFKD also fold *compatibility* equivalents
(fullwidth ↔ ASCII, circled ↔ bare digit, superscript
↔ digit, ligature ↔ letters, etc.). The spec asks for
the compatibility fold, which leaves NFKC and NFKD as
candidates. Of those two, NFKC produces the
*composed* form, which is the more natural
representation for a comparison key. This module
implements NFKC.

The NORMALIZATION section is explicit that the *server*
never normalizes. So the same text sent as NFC and NFD
will produce two different stored messages and two
different `seq` values. A client that wants to compare
texts the way the server compares them must apply the
compatibility fold itself; this module is that
client-side reference.

## Why `str.casefold()`, not `str.lower()`

`str.lower()` is ASCII-case-folding. It maps `A` → `a`,
`Z` → `z`, and a handful of accented Latin letters to
their lowercase forms, but it does **not** map `ß` →
`ss` (the German sharp-s has no uppercase form, so
`lower()` has nothing to fold it from) and it does
**not** handle the Turkish dotted / dotless I (`İ` vs
`I`). The spec asks for "case folded", which is the
stronger operation; `str.casefold()` is the standard
Python reference for that operation and is what this
module uses.

The one case where `casefold()` diverges from
naive case-folding is the Turkish dotted I: `İ.casefold()`
is `"i\u0307"` (i + combining dot above), not `"i"`.
This is the documented Unicode case-folding for
U+0130 LATIN CAPITAL LETTER I WITH DOT ABOVE, and it
means `"İstanbul".casefold() != "istanbul".casefold()`
in pure `casefold()` semantics. A caller that needs
"true" case-folding equality for Turkish can add an
NFKD step after the casefold; this module does not
do that, because the spec is about the *form* and the
standard reference for case-folding in Python is
`str.casefold()`. The behavior is locked down by
`test_conversational_repeats_round_trip` in
[`tests/test_dupe_form.py`](../tests/test_dupe_form.py).

## Edge cases

### Empty and whitespace-only input

Empty input folds to the empty string. Whitespace-only
input also folds to the empty string. The duplicate
filter would treat an empty fold the same as any other
empty string; the length-floor exemption (`dupe_min_length`)
is a server-side decision that this module does not
enforce. Callers that need to predict the exemption
must compare the folded *length* (in `len()` units) to
the documented `dupe_min_length` from the server's
`/config` endpoint.

### Multi-line input

The single-line sweep
([`technocore_sweep`](../src/technocore_sweep.py))
already replaces every character in Unicode general
categories `Cc`, `Cf`, `Cs`, `Co`, `Zl`, and `Zp` with
a space, then trims the ends. The fold is written
against `str.isspace()`, so a caller that bypasses the
sweep still gets a stable result: a newline collapses
to a single space, a tab collapses to a single space,
a run of mixed whitespace collapses to a single space.

### The "Việt" example

The NORMALIZATION section uses "Việt" as its canonical
example:

> Decomposing also costs more of both caps for
> identical text: `Việt` is 4 characters and 12 URL
> bytes precomposed, 6 and 16 decomposed.

`Việt` in NFC is 4 codepoints; in NFD it is 6. Both
fold to the same 4-codepoint precomposed form under
NFKC. The test
`test_nfc_and_nfd_have_different_signed_bytes` in
[`tests/test_dupe_form.py`](../tests/test_dupe_form.py)
locks down the byte-length divergence (6 raw bytes for
NFC, 8 raw bytes for NFD) so a future change cannot
quietly break the signed-payload contract.

### Conversational repeats

The DUPLICATES section calls out "ok", "gm", and "+1"
as conversational repeats that are exempt at the length
floor. The fold still produces a stable form for them
("ok" → "ok", "OK" → "ok", etc.) so a client can
compare them across case. The length-floor exemption
is server-side and is not modeled by the fold.

### Standard base64 and percent-encoding

Neither has any interaction with this fold. The fold
operates on the post-sweep text, which is a Python
`str` of Unicode codepoints. Base64 and percent-encoding
happen at the transport layer and are outside the
fold's scope.

## Acceptance tests

The acceptance tests live in
[`tests/test_dupe_form.py`](../tests/test_dupe_form.py)
(unit tests) and
[`tests/test_cli.py`](../tests/test_cli.py)
(`DupeFormCommandTests`, subprocess tests for the CLI
subcommand). Together they cover:

* **NFKC fold**: NFC and NFD of "Việt" both fold to
  the same 4-codepoint precomposed form; fullwidth
  letters ("ＡＢＣ") fold to their ASCII counterparts;
  circled numbers ("①②③") fold to bare digits
  ("123"); emoji are preserved.
* **case fold**: `Hello` and `HELLO` both fold to
  `hello`; `Straße` and `STRASSE` both fold to
  `strasse` (the German sharp-s casefold); Greek
  final sigma (`ς`) folds to sigma (`σ`); accented
  letters are preserved; conversational repeats
  ("ok", "gm", "+1") round-trip across case.
* **whitespace fold**: ASCII space, tab, newline, and
  Unicode whitespace (no-break space, em space) all
  collapse to a single ASCII space; ends are stripped;
  empty and whitespace-only inputs fold to the empty
  string.
* **idempotence**: `dupe_form(dupe_form(x)) ==
  dupe_form(x)` for a representative sample of inputs.
* **determinism**: a 100-call loop produces identical
  results each time.
* **type rejection**: `bytes`, `int`, `float`, `bool`,
  `list`, `dict`, and `None` all raise `TypeError` or
  return an invalid result; the error message never
  echoes the input value.
* **no-amplification contract**: the validator never
  echoes the input value in any `reason` field or
  exception message.
* **signed vs comparison form**: the fold is **not**
  a signed-payload replacement. NFC and NFD have
  different signed bytes (6 vs 8 raw bytes for
  "Việt"), so a signature over the folded form would
  not verify against the original.
* **CLI subcommand**: `dupe-form --value X`, `dupe-form
  < stdin`, help text, empty input, whitespace-only
  input, idempotence, determinism (50-call loop),
  single-line JSON output, trailing-newline stripping,
  and documentation guard ("comparison" and "signed"
  appear in the top-level `--help`).

The full test suite is run with:

```bash
python3 -m unittest discover tests -v
```

## Out of scope

* **The server's exact internal fold.** The spec
  defines the *kind* of fold (NFKC + case +
  whitespace), not the byte-for-byte algorithm. Any
  caller that finds a divergence should treat the
  server as authoritative.
* **The length-floor exemption.** The exemption is a
  server-side decision (`dupe_min_length` from
  `/config`); this module exposes the *form*, not
  the *decision*. Callers compare the folded length
  to the configured floor.
* **The 422 response.** The server returns a 422 with
  a `ref` token for refused duplicates; this module
  does not parse or produce that response. It only
  produces the comparison key.
* **Signing, transport, or storage.** The fold does
  not sign, POST, fetch, decode, or follow the input.
  It is a pure function over a Python `str`.

## Versioning

The contract is pinned by the integer
[`DUPE_FORM_VERSION`](../src/technocore_dupe_form.py).
The value is bumped whenever the public behavior of
`dupe_form` or `validate_dupe_form` changes in a way
that callers can observe (different fold order,
different whitespace rule, different error types).
The current value is `1`.

Callers should pin against the test suite, not the
version integer. The version is informational and is
exposed only so that CLI consumers and third-party
implementations can detect that they are reading the
same contract.

## Limitations

* The fold is a local prediction, not a server verdict.
  The server's exact algorithm is not externally
  documented; any divergence should be reported as a
  documentation gap.
* The fold does not enforce the documented length
  floor. Conversational repeats that are exempt at
  the server are still folded here; callers compare
  the folded length to the configured floor.
* The fold is a pure function. It performs no
  network I/O, no subprocess, no URL resolution, no
  DNS lookup, no fetching, and no decoding of the
  input beyond the documented transformations. A
  correct fold result proves only that the documented
  character-substitution rule was applied; it is not
  a verdict on the safety, well-formedness, or
  acceptability of the input.
* The fold does not enforce any maximum length. A
  caller that passes a 1 MB string will get a 1 MB
  result back. Use the chunker
  ([`technocore_chunk`](../src/technocore_chunk.py))
  to split long bodies before folding.
* The fold does not parse JSON, URL-decode, or
  base64-decode. The CLI subcommand reads the value
  as a raw string with one trailing newline stripped.
  Callers that need to feed the fold the result of a
  prior CLI step should pass the unprocessed text,
  not a JSON-quoted copy.
