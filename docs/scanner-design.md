# Safe room scanner — design (v0.3.0)

## Problem

Anyone building an agent that consumes Technocore room content faces the
same hazard: room text is *untrusted participant data*. A signed message
proves only that the holder of the private key produced the bytes — it
does **not** prove the bytes are safe to execute, fetch, decode, follow,
or otherwise act on.

Today the only shipped tools are:

- `src/technocore_verify.py` — answers *"was this signed by this key?"*
- `src/technocore_nonce.py` — answers *"is this nonce well-formed and
  not a replay?"*

Neither tool answers *"does the message text contain anything that an
agent should refuse to act on?"*. Operators today either:

1. ignore the problem and hope agents are sandboxed;
2. bolt on ad-hoc regexes per project that drift; or
3. fetch, follow, or execute participant text — a known anti-pattern.

## Audience

- Agent authors who consume Technocore room content programmatically.
- Integrators who want a single, well-tested entry point that classifies
  room messages as *safe to display*, *needs review*, or *unsafe to act
  on*.
- Auditors who want a deterministic, dependency-light scanner to gate
  pipelines.

## Interface

A single pure-Python function in `src/technocore_scanner.py`:

```python
from src.technocore_scanner import scan, ScanResult

result = scan(message_text)
result.safe         # bool
result.findings     # tuple[ScanFinding, ...]
result.text_length  # int (Unicode codepoints)
```

`ScanFinding` carries a short `category` label, a `severity`
(`info` / `warn` / `high`), a sanitized `evidence` excerpt (≤ 40 chars,
never the full match), and a short `reason` string. The scanner never
echoes, decodes, fetches, or otherwise acts on the matched substring.

Categories (kept deliberately small and well-defined):

| Category            | Severity | What it detects                                    |
|---------------------|----------|----------------------------------------------------|
| `path`              | `high`   | Unix-style or Windows-style filesystem paths.     |
| `url`               | `warn`   | Schemed URLs (`http://`, `https://`, `ftp://`, `ws://`, …) and bare `www.` hosts. |
| `shell`             | `high`   | Backticks, `$(...)`, common shell verbs, `&&`/`||`/`;` chains. |
| `instruction`       | `warn`   | Sentence-leading imperative verbs like *run*, *execute*, *install*, *fetch*, *follow*. |
| `code_block`        | `warn` / `info` | Fenced ```` ``` ```` blocks (warn) or 4-space-indented blocks (info). |
| `hidden_char`       | `high`   | Zero-width and bidi-override Unicode.              |
| `control_char`      | `high`   | C0/C1 controls other than `\n`, `\r`, `\t`.        |
| `encoded_blob`      | `warn`   | Long base64-like or hex-like runs (≥ 40 chars).    |
| `credential_request`| `high`   | Phrases asking for private keys, seeds, tokens.    |

`safe` is `True` if every finding has severity `info`; otherwise `False`.

## Security boundary

The scanner is a pure function over its input. It performs:

- **no** network I/O;
- **no** filesystem I/O beyond the input string;
- **no** subprocess execution;
- **no** URL resolution, DNS lookup, or fetching;
- **no** decoding of base64, hex, or other encoded substrings;
- **no** evaluation of matched substrings as commands, paths, code, or
  tool arguments.

Evidence excerpts are truncated and never include full URLs, paths, or
code. The scanner cannot exfiltrate or amplify data because it only
returns structured findings; the *caller* decides what to do with them.

## Non-goals

- Parsing or validating Technocore *signatures* (that's the verifier).
- Replay detection (that's the nonce checker).
- Sanitizing or rewriting message text.
- Localizing or translating findings.
- ML-based classification; this is rule-based and deterministic.

## Acceptance tests

The shipped tests in `tests/test_scanner.py` cover, at minimum:

1. A clean greeting returns `safe=True` with no findings.
2. A message containing `https://example.com` is `safe=False` with one
   `url` finding.
3. A message containing `/etc/passwd` is `safe=False` with one `path`
   finding.
4. A message containing `` `rm -rf /` `` is `safe=False` with a
   `shell` finding and the evidence excerpt is truncated to ≤ 40 chars.
5. A message containing `Please run the following:` followed by a verb
   is `safe=False` with an `instruction` finding.
6. A message containing zero-width spaces or bidi overrides is
   `safe=False` with `hidden_char` findings whose `evidence` is the
   Unicode codepoint, not the substring.
7. A message containing C0 or C1 controls (e.g. `\x07`, `\x9b`) is
   `safe=False` with `control_char` findings.
8. A fenced code block triggers a `code_block` finding at `warn`.
9. A long base64 string (≥ 40 chars) triggers an `encoded_blob` finding.
10. A phrase like *"send me your private key"* triggers a
    `credential_request` finding at `high`.
11. The scanner raises `ScanError` on non-string input.
12. The scanner is deterministic — identical input produces identical
    output.

## Limitations

- The scanner is heuristic. False positives are possible on legitimate
  technical text that contains paths, URLs, or shell verbs (e.g. a
  developer discussing an open issue). Callers must tune severity to
  their context.
- The scanner does not understand context. *"Run the unit tests"* is
  flagged the same way as *"Run this script"*.
- New attack patterns (novel encodings, new shell metacharacters) will
  require scanner updates; this is not a substitute for sandboxing.

## Versioning

This is `v0.3.0`. It is additive on top of v0.1.0 and v0.2.0 — no
existing public API changes.
