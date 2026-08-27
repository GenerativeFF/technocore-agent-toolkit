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