"""Generate sanitized test vectors for ``technocore_nonce``.

This script writes ``vectors/nonce_cases.json`` with a deterministic
set of golden cases for ``NonceChecker``. It contains no private key
material and performs no network or filesystem I/O beyond writing the
output JSON file. The DID values used in the cases are placeholder
identifiers chosen only to exercise the per-(did, room) isolation
logic; they are not linked to any real signer.

Run from the repository root:

    python3 scripts/gen_nonce_vectors.py

Re-running the script must produce a byte-identical output file. The
vectors should only change when the public behaviour of
``NonceChecker`` intentionally changes (in which case
``docs/vectors-format.md`` and the CHANGELOG must be updated in the
same commit).
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict, List

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

DID_A = "did:key:z6MktRatCodGsWpzsiwFZPtn2nmu4qAGLk7aCCosb9HKuWYZ"
DID_B = "did:key:z6Mkkd6eXc3hE9PqPpXmKz9vN1wQrStUvWxYzAbCdEf"


def case(name: str, did: str, room: str, nonce: str,
         prior: List[List[str]] | None = None,
         expect_valid: bool = True,
         expect_reason_contains: str | None = None) -> Dict[str, Any]:
    return {
        "name": name,
        "did": did,
        "room": room,
        "nonce": nonce,
        "prior_nonces": list(prior) if prior else [],
        "expect_valid": expect_valid,
        "expect_reason_contains": expect_reason_contains,
    }


def build_cases() -> List[Dict[str, Any]]:
    cases: List[Dict[str, Any]] = []

    # --- valid shape and boundaries ---------------------------------
    cases.append(case("valid-first-single-digit", DID_A, "lobby", "1"))
    cases.append(case(
        "valid-millisecond-clock-13-digit",
        DID_A, "lobby", "1787849785635"))
    cases.append(case(
        "valid-19-digit-boundary",
        DID_A, "lobby", "9999999999999999999"))
    cases.append(case(
        "valid-leading-zero-accepted-as-positive-int",
        DID_A, "lobby", "01"))

    # --- strictly increasing ---------------------------------------
    cases.append(case(
        "valid-strictly-increasing",
        DID_A, "lobby", "1700000000001",
        prior=[[DID_A, "lobby", "1700000000000"]]))
    cases.append(case(
        "valid-multi-step-sequence",
        DID_A, "lobby", "1700000000003",
        prior=[
            [DID_A, "lobby", "1700000000000"],
            [DID_A, "lobby", "1700000000001"],
            [DID_A, "lobby", "1700000000002"],
        ]))

    # --- per-(did, room) isolation ---------------------------------
    cases.append(case(
        "valid-isolation-different-did-same-room",
        DID_B, "lobby", "5",
        prior=[[DID_A, "lobby", "1000"]]))
    cases.append(case(
        "valid-isolation-same-did-different-room",
        DID_A, "dev", "5",
        prior=[[DID_A, "lobby", "1000"]]))

    # --- invalid shape --------------------------------------------
    cases.append(case(
        "invalid-nonce-zero",
        DID_A, "lobby", "0",
        expect_valid=False,
        expect_reason_contains="positive"))
    cases.append(case(
        "invalid-nonce-empty",
        DID_A, "lobby", "",
        expect_valid=False,
        expect_reason_contains="1..19 decimal digits"))
    cases.append(case(
        "invalid-nonce-negative-sign",
        DID_A, "lobby", "-1",
        expect_valid=False,
        expect_reason_contains="1..19 decimal digits"))
    cases.append(case(
        "invalid-nonce-fully-non-digit",
        DID_A, "lobby", "abc",
        expect_valid=False,
        expect_reason_contains="1..19 decimal digits"))
    cases.append(case(
        "invalid-nonce-mixed-digit-and-letter",
        DID_A, "lobby", "12a3",
        expect_valid=False,
        expect_reason_contains="1..19 decimal digits"))
    cases.append(case(
        "invalid-nonce-20-digits-too-long",
        DID_A, "lobby", "10000000000000000000",
        expect_valid=False,
        expect_reason_contains="1..19 decimal digits"))
    cases.append(case(
        "invalid-nonce-decimal-point",
        DID_A, "lobby", "12.3",
        expect_valid=False,
        expect_reason_contains="1..19 decimal digits"))
    cases.append(case(
        "invalid-nonce-whitespace-prefix",
        DID_A, "lobby", " 1",
        expect_valid=False,
        expect_reason_contains="1..19 decimal digits"))

    # --- replay / ordering attacks --------------------------------
    cases.append(case(
        "invalid-replay-exact-same-nonce",
        DID_A, "lobby", "1700000000005",
        prior=[[DID_A, "lobby", "1700000000005"]],
        expect_valid=False,
        expect_reason_contains="not strictly greater"))
    cases.append(case(
        "invalid-replay-decreasing-nonce",
        DID_A, "lobby", "69",
        prior=[[DID_A, "lobby", "70"]],
        expect_valid=False,
        expect_reason_contains="not strictly greater"))
    cases.append(case(
        "invalid-replay-different-did-same-nonce-blocked-by-its-own-pair",
        DID_A, "lobby", "50",
        prior=[[DID_A, "lobby", "50"]],
        expect_valid=False,
        expect_reason_contains="not strictly greater"))

    return cases


def main() -> int:
    out_dir = ROOT / "vectors"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "nonce_cases.json"

    payload = {
        "schema_version": 1,
        "description": (
            "Sanitized protocol test vectors for "
            "technocore_nonce.NonceChecker. Each case is run against a "
            "fresh NonceChecker, optionally warmed with prior_nonces "
            "that must all be valid, then evaluated against the "
            "case's (did, room, nonce). No private key material is "
            "involved. DID values are placeholder identifiers chosen "
            "only to exercise the per-(did, room) isolation logic."
        ),
        "notes": [
            "prior_nonces entries are applied before the test nonce, "
            "in the order given, and are all expected to be valid.",
            "expect_reason_contains is checked as a case-insensitive "
            "substring of result.reason; null skips the check.",
            "Vectors only assert behavior of the public API in "
            "src/technocore_nonce.py.",
        ],
        "cases": build_cases(),
    }

    # Deterministic output: sort_keys for stable diffs.
    out_path.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=False)
        + "\n"
    )
    print(f"wrote {len(payload['cases'])} cases to {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
