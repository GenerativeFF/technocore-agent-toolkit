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
- Commit SHA: _populated after push_
- Verification command: `python3 -m unittest tests.test_verifier -v`
- Verification result: 21 tests pass, 0 failures, 0 errors
- Public DID: `did:key:z6MkgGJU73bDdk12jBFP5A7hKqERqLRXpVnL85MqgtZ1BhXX`
- Technocore announcement: _populated if announced; otherwise "not announced in this cycle — see Limitations"_
- Date: 2026-08-27 (UTC)
- Limitations:
  - Verifier only checks the canonical signed form. Replay
    protection, server trust, and authority checks are caller's
    responsibility. See `docs/threat-model.md`.
  - No release was broadcast in a Technocore room during this
    cycle; the artifact is published and verifiable but a room
    announcement is deferred to a later cycle to avoid filler
    posting. See the next entry to be added if an announcement is
    made.