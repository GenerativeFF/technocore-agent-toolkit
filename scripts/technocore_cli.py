#!/usr/bin/env python3
"""Command-line interface for the technocore-agent-toolkit modules.

This script exposes the three pure-Python Technocore building blocks
(``technocore_verify``, ``technocore_nonce``, ``technocore_scanner``)
as small, stdlib-only subcommands suitable for shell pipelines,
CI checks, and quick local debugging. It performs no network I/O,
no subprocess execution, and no filesystem writes.

Subcommands
-----------

``scan`` — classify a text payload for untrusted-content hazards.

    python3 scripts/technocore_cli.py scan [--file PATH] [--json]
    # text is read from PATH, or from stdin when PATH is omitted.

``verify`` — verify a signed room-message payload against an
optional raw Ed25519 public key and/or optional expected DID.

    python3 scripts/technocore_cli.py verify \\
        --payload PATH [--public-key HEX] [--expected-did DID]
    # payload JSON is read from PATH, or from stdin when PATH is omitted.

``nonce-check`` — validate the shape of a nonce (1..19 decimal
digits, positive integer). The on-protocol strictly-increasing
ordering check is intentionally not exposed here, because the
ordering state is process-local; pair this command with the
``NonceChecker`` Python API for replay protection.

    python3 scripts/technocore_cli.py nonce-check \\
        --did DID --room ROOM --nonce NONCE

Output
------

Every subcommand emits exactly one JSON object on stdout. The
object always has a top-level ``ok`` boolean (``true`` when the
command ran successfully; ``false`` for input-validation errors).
For successful runs, the tool-specific verdict is in a
``result`` field. Errors and validation failures are written as
a JSON object with ``ok=false`` and an ``error`` field, plus an
exit code:

* exit ``0`` — command ran; inspect ``result.valid`` for the
  semantic verdict.
* exit ``2`` — argument validation failed (printed on stderr).
* exit ``3`` — payload could not be parsed/evaluated as a
  signed-message structure (e.g. malformed JSON, missing
  fields, bad base64url, wrong signature length).

All inputs are treated as untrusted data. Nothing is executed,
fetched, decoded, or followed. The script uses only the Python
standard library plus the project's own modules.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, NoReturn

# Make the in-tree src/ package importable when this script is
# invoked directly (it lives in scripts/, not at the repo root).
_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO = os.path.dirname(_HERE)
_SRC = os.path.join(_REPO, "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

# pylint: disable=wrong-import-position
from technocore_nonce import NonceCheckResult, NonceChecker  # noqa: E402
from technocore_scanner import ScanError, ScanResult, scan as scanner_scan  # noqa: E402
from technocore_verify import (  # noqa: E402
    VerifyResult,
    VerifierError,
    verify as verifier_verify,
)

# Re-exported so tests can import them from one place if needed.
__all__ = ["main"]


# ---------------------------------------------------------------------------
# JSON helpers
# ---------------------------------------------------------------------------


def _emit(payload: dict[str, Any]) -> NoReturn:
    """Write a one-line JSON object to stdout and exit 0."""
    json.dump(payload, sys.stdout, ensure_ascii=True, sort_keys=True)
    sys.stdout.write("\n")
    sys.stdout.flush()
    sys.exit(0)


def _fail(error: str, code: int) -> NoReturn:
    """Write a JSON error to stderr and exit with the given code."""
    json.dump(
        {"ok": False, "error": error},
        sys.stderr,
        ensure_ascii=True,
        sort_keys=True,
    )
    sys.stderr.write("\n")
    sys.stderr.flush()
    sys.exit(code)


# ---------------------------------------------------------------------------
# Input readers (always treat as untrusted data)
# ---------------------------------------------------------------------------


def _read_text_arg(args: argparse.Namespace, attr: str = "file") -> str:
    """Return text from ``--file`` or stdin. Path is validated."""
    path = getattr(args, attr, None)
    if path is None or path == "-":
        return sys.stdin.read()
    if not isinstance(path, str):
        _fail(f"--{attr.replace('_', '-')} must be a string path", 2)
    if not os.path.isfile(path):
        _fail(f"--{attr.replace('_', '-')} path does not exist or is not a file: {path}", 2)
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return fh.read()
    except OSError as exc:
        _fail(f"could not read --{attr.replace('_', '-')} file: {exc}", 2)


def _read_payload_arg(args: argparse.Namespace) -> dict[str, Any]:
    """Return the payload mapping from --payload JSON file or stdin."""
    raw = _read_text_arg(args, attr="payload")
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        _fail(f"payload is not valid JSON: {exc.msg}", 3)
    if not isinstance(data, dict):
        _fail("payload must be a JSON object", 3)
    return data


# ---------------------------------------------------------------------------
# Subcommands
# ---------------------------------------------------------------------------


def _result_to_dict_scan(result: ScanResult) -> dict[str, Any]:
    """Convert a ``ScanResult`` to a JSON-friendly dict."""
    findings = [
        {
            "category": f.category,
            "severity": f.severity,
            "evidence": f.evidence,
            "reason": f.reason,
        }
        for f in result.findings
    ]
    return {
        "safe": bool(result.safe),
        "text_length": int(result.text_length),
        "findings": findings,
    }


def _result_to_dict_verify(result: VerifyResult) -> dict[str, Any]:
    """Convert a ``VerifyResult`` to a JSON-friendly dict."""
    return {
        "valid": bool(result.valid),
        "did": result.did,
        "fingerprint": result.fingerprint,
        "reason": result.reason,
        "canonical_sha256": result.canonical_sha256,
    }


def _result_to_dict_nonce(result: NonceCheckResult) -> dict[str, Any]:
    """Convert a ``NonceCheckResult`` to a JSON-friendly dict."""
    return {
        "valid": bool(result.valid),
        "reason": result.reason,
    }


def cmd_scan(args: argparse.Namespace) -> NoReturn:
    text = _read_text_arg(args, attr="file")
    try:
        result = scanner_scan(text)
    except ScanError as exc:
        _fail(f"scan failed: {exc}", 3)
    _emit({"ok": True, "command": "scan", "result": _result_to_dict_scan(result)})


def cmd_verify(args: argparse.Namespace) -> NoReturn:
    payload = _read_payload_arg(args)
    public_key: bytes | None = None
    if args.public_key is not None:
        if not isinstance(args.public_key, str):
            _fail("--public-key must be a string", 2)
        raw = args.public_key.strip()
        try:
            public_key = bytes.fromhex(raw)
        except ValueError as exc:
            _fail(f"--public-key is not valid hex: {exc}", 2)
        if len(public_key) != 32:
            _fail(
                f"--public-key must decode to 32 bytes, got {len(public_key)}",
                2,
            )
    expected_did: str | None = args.expected_did
    if expected_did is not None and not isinstance(expected_did, str):
        _fail("--expected-did must be a string", 2)
    try:
        result = verifier_verify(
            payload,
            public_key,
            expected_did=expected_did,
        )
    except VerifierError as exc:
        _fail(f"verify failed: {exc}", 3)
    _emit(
        {"ok": True, "command": "verify", "result": _result_to_dict_verify(result)}
    )


def cmd_nonce_check(args: argparse.Namespace) -> NoReturn:
    for flag in ("did", "room", "nonce"):
        value = getattr(args, flag, None)
        if not isinstance(value, str) or not value:
            _fail(f"--{flag.replace('_', '-')} is required and must be non-empty", 2)
    # The NonceChecker is a stateful in-process object. The CLI
    # exposes only the shape-validation surface, since multi-call
    # state cannot be safely persisted across processes from a
    # stateless command. Callers needing replay protection should
    # use the NonceChecker Python API directly with their own
    # backing store.
    checker = NonceChecker()
    result: NonceCheckResult = checker.check_and_update(
        args.did, args.room, args.nonce
    )
    _emit(
        {
            "ok": True,
            "command": "nonce-check",
            "result": _result_to_dict_nonce(result),
        }
    )


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="technocore-cli",
        description=(
            "Command-line interface for technocore-agent-toolkit. "
            "All subcommands read untrusted input, perform no network "
            "or subprocess I/O, and emit exactly one JSON object on stdout."
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser(
        "scan",
        help="Scan text for untrusted-content hazards.",
    )
    p_scan.add_argument(
        "--file",
        "-f",
        default=None,
        help=(
            "Path to a UTF-8 text file. If omitted or set to '-', "
            "the text is read from stdin."
        ),
    )
    p_scan.set_defaults(func=cmd_scan)

    p_verify = sub.add_parser(
        "verify",
        help="Verify a Technocore signed-message payload.",
    )
    p_verify.add_argument(
        "--payload",
        "-p",
        default=None,
        help=(
            "Path to a JSON payload file. If omitted or set to '-', "
            "the payload JSON is read from stdin."
        ),
    )
    p_verify.add_argument(
        "--public-key",
        default=None,
        help=(
            "Optional 32-byte raw Ed25519 public key as hex. "
            "Must match the DID in the payload when provided."
        ),
    )
    p_verify.add_argument(
        "--expected-did",
        default=None,
        help="Optional DID string the signer must match.",
    )
    p_verify.set_defaults(func=cmd_verify)

    p_nonce = sub.add_parser(
        "nonce-check",
        help="Validate the shape of a (did, room, nonce) triple.",
    )
    p_nonce.add_argument("--did", required=True, help="DID of the signer.")
    p_nonce.add_argument("--room", required=True, help="Room slug.")
    p_nonce.add_argument("--nonce", required=True, help="Nonce string to check.")
    p_nonce.set_defaults(func=cmd_nonce_check)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        args.func(args)
    except SystemExit:
        raise
    except Exception as exc:  # noqa: BLE001 - top-level safety net
        _fail(f"unexpected error: {exc}", 1)
    return 0  # unreachable; subcommands sys.exit


if __name__ == "__main__":
    raise SystemExit(main())
