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

``nonce-safety`` — structured safety assessment of a nonce
string. Reports shape validity (1..19 decimal digits, positive
integer), whether the integer fits exactly in an IEEE 754 double
(so a non-Python caller does not silently lose precision when
the JSON number is decoded as a ``double``), the bit length of
the integer, and whether the bit length falls below a caller-
supplied entropy threshold (default 32 bits). Pure function, no
state, no network I/O.

    python3 scripts/technocore_cli.py nonce-safety [--value NONCE] [--min-bits N]
    # value is read from --value, or from stdin when --value is omitted.

``nonce-check`` — validate the shape of a nonce (1..19 decimal
digits, positive integer). The on-protocol strictly-increasing
ordering check is intentionally not exposed here, because the
ordering state is process-local; pair this command with the
``NonceChecker`` Python API for replay protection.

    python3 scripts/technocore_cli.py nonce-check \\
        --did DID --room ROOM --nonce NONCE

``chunk`` — split a text payload into pieces, each no longer than
``--max-len`` codepoints. Useful for posting long messages that
exceed the documented per-message size cap. Emits one JSON object
on stdout with the chunk count, the requested ``max_len``, the
default ``max_len``, the contract ``version``, and an ordered list
of ``{index, length, text}`` objects. The chunker is a pure
function: it does not sign, POST, or otherwise transmit the text.

    python3 scripts/technocore_cli.py chunk [--max-len N] [--file PATH]
    # text is read from PATH, or from stdin when PATH is omitted.

``sig-shape`` — validate the *surface* canonical form of a
candidate Technocore signature string (length 86, unpadded
base64url alphabet, last char in ``{A, Q, g, w}``). This is a
fast, allocation-light pre-filter for callers that want to reject
malformed signatures before paying for a cryptographic
verification. The signature string is read from ``--value`` or
stdin. Emits one JSON object on stdout with ``valid``, ``reason``
(when invalid), and a ``version`` field. The validator is a pure
function: it does not verify the signature cryptographically,
does not sign, POST, or otherwise transmit the value.

    python3 scripts/technocore_cli.py sig-shape [--value STRING]
    # value is read from --value, or from stdin when --value is omitted.

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
# Add both the repo root and the src/ directory: the project's
# modules use ``from src.X import ...`` for cross-references (e.g.
# ``technocore_verify`` imports ``technocore_sweep``), and the
# CLI itself imports them with the ``src.`` prefix stripped. Having
# both on sys.path lets every import shape resolve.
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

# pylint: disable=wrong-import-position
from technocore_chunk import (  # noqa: E402
    CHUNK_VERSION as CHUNKER_CHUNK_VERSION,
    DEFAULT_MAX_LEN as CHUNKER_DEFAULT_MAX_LEN,
    ChunkError,
    chunk_message,
)
from technocore_nonce import (  # noqa: E402
    DEFAULT_MIN_BITS as NONCE_DEFAULT_MIN_BITS,
    NONCE_SAFETY_VERSION,
    NonceCheckResult,
    NonceChecker,
    NonceSafetyResult,
    nonce_safety_assessment,
)
from technocore_scanner import ScanError, ScanResult, scan as scanner_scan  # noqa: E402
from technocore_sig_shape import (  # noqa: E402
    SIG_SHAPE_VERSION,
    SigShapeError,
    SigShapeResult,
    is_canonical_signature_shape,
    validate_signature_shape,
)
from technocore_dupe_form import (  # noqa: E402
    DUPE_FORM_VERSION,
    DupeFormError,
    DupeFormResult,
    dupe_form as dupe_form_fold,
    validate_dupe_form,
)
from technocore_dupe_exempt import (  # noqa: E402
    DUPE_EXEMPT_VERSION,
    DupeExemptError,
    DupeExemptResult,
    dupe_exempt as dupe_exempt_check,
    validate_dupe_exempt,
)
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


def _result_to_dict_nonce_safety(result: NonceSafetyResult) -> dict[str, Any]:
    """Convert a ``NonceSafetyResult`` to a JSON-friendly dict.

    The ``valid`` boolean is always present, the ``reason`` is
    included only when the verdict is invalid, and the contract
    ``version`` is included on every successful run so callers can
    pin against it. The float53 and entropy fields are only
    meaningful when ``valid`` is True; they are still emitted on
    every successful run so callers can branch on them without
    having to introspect the ``valid`` flag first.
    """
    out: dict[str, Any] = {
        "valid": bool(result.valid),
        "version": int(result.version),
    }
    if not result.valid:
        out["reason"] = result.reason
    else:
        out["fits_in_float53"] = bool(result.fits_in_float53)
        out["bit_length"] = int(result.bit_length)
        out["entropy_warning"] = bool(result.entropy_warning)
    return out


def _result_to_dict_chunk(chunks: list[str], max_len: int) -> dict[str, Any]:
    """Convert a chunker output to a JSON-friendly dict.

    Each chunk's length is reported alongside the chunk itself so a
    caller can spot oversize chunks (single tokens longer than
    ``max_len``) without having to recount codepoints. The list of
    chunks is emitted in original order; the round-trip property
    means ``"".join(chunks) == text`` for every legal input.
    """
    return {
        "chunk_count": len(chunks),
        "max_len": int(max_len),
        "default_max_len": int(CHUNKER_DEFAULT_MAX_LEN),
        "version": int(CHUNKER_CHUNK_VERSION),
        "chunks": [
            {"index": idx, "length": len(c), "text": c}
            for idx, c in enumerate(chunks)
        ],
    }


def _result_to_dict_sig_shape(result: SigShapeResult) -> dict[str, Any]:
    """Convert a ``SigShapeResult`` to a JSON-friendly dict.

    The ``valid`` boolean is always present, the ``reason`` is
    included only when the verdict is invalid, and the contract
    ``version`` is included on every successful run so callers can
    pin against it. The validator never echoes the input value
    onto any channel; ``reason`` is a static, parameter-free string.
    """
    out: dict[str, Any] = {"valid": bool(result.valid), "version": int(SIG_SHAPE_VERSION)}
    if not result.valid:
        out["reason"] = result.reason
    return out


def _result_to_dict_dupe_form(result: DupeFormResult) -> dict[str, Any]:
    """Convert a ``DupeFormResult`` to a JSON-friendly dict.

    The ``valid`` boolean is always present, ``folded`` carries
    the canonical duplicate-filter form when ``valid`` is True,
    the ``reason`` is included only when ``valid`` is False, and
    the contract ``version`` is included on every successful run
    so callers can pin against it. The validator never echoes
    the input value onto any channel; ``reason`` is a static,
    parameter-free string, and ``folded`` is the *transformed*
    output, not the input.
    """
    out: dict[str, Any] = {"valid": bool(result.valid), "version": int(DUPE_FORM_VERSION)}
    if result.valid:
        out["folded"] = result.folded
    else:
        out["reason"] = result.reason
    return out


def _result_to_dict_dupe_exempt(result: DupeExemptResult) -> dict[str, Any]:
    """Convert a ``DupeExemptResult`` to a JSON-friendly dict.

    On a successful run, the JSON carries ``exempt`` (whether
    the folded text is strictly shorter than the supplied
    floor), ``folded_length`` (codepoint count of the folded
    form), ``min_length`` (the floor the caller supplied,
    echoed back for logging), and ``folded`` (the canonical
    comparison form, identical to what ``dupe-form`` would
    return for the same input). On a failed run, only
    ``valid: false`` and a static ``reason`` are returned; no
    field of the original input is echoed.

    The contract ``version`` is included on every successful
    run so callers can pin against it.
    """
    out: dict[str, Any] = {"valid": bool(result.valid), "version": int(DUPE_EXEMPT_VERSION)}
    if result.valid:
        out["exempt"] = bool(result.exempt)
        out["folded"] = result.folded
        out["folded_length"] = int(result.folded_length) if result.folded_length is not None else None
        out["min_length"] = int(result.min_length) if result.min_length is not None else None
    else:
        out["reason"] = result.reason
    return out


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


def cmd_nonce_safety(args: argparse.Namespace) -> NoReturn:
    # The nonce string is read from --value or stdin (the same
    # convention as ``sig-shape`` and ``dupe-form``). The assessment
    # is a pure function over its input: it does not call the
    # network, does not read a room, and does not record anything.
    value = getattr(args, "value", None)
    if value is None:
        value = sys.stdin.read()
    elif not isinstance(value, str):
        _fail("--value must be a string", 2)
    # Strip exactly one trailing newline so piping a nonce string
    # into the CLI does not add a bogus 20th character (which would
    # always be rejected by the shape check anyway). A pre-existing
    # newline anywhere else in the string is preserved.
    if value.endswith("\n") and len(value) >= 1:
        value = value[:-1]
    # ``--min-bits`` is parsed by ``type=int`` so a non-int input
    # already exits 2 with an argparse error before we get here;
    # we still defensively guard against ``bool`` and non-positive
    # values so the CLI matches the Python API's error surface.
    min_bits = getattr(args, "min_bits", NONCE_DEFAULT_MIN_BITS)
    if isinstance(min_bits, bool) or not isinstance(min_bits, int):
        _fail("--min-bits must be an int", 2)
    if min_bits <= 0:
        _fail("--min-bits must be a positive integer", 2)
    try:
        result = nonce_safety_assessment(value, min_bits=min_bits)
    except TypeError as exc:
        _fail(f"nonce-safety failed: {exc}", 3)
    except ValueError as exc:
        _fail(f"nonce-safety failed: {exc}", 3)
    _emit(
        {
            "ok": True,
            "command": "nonce-safety",
            "result": _result_to_dict_nonce_safety(result),
        }
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


def cmd_chunk(args: argparse.Namespace) -> NoReturn:
    # ``--max-len`` is parsed by ``type=int`` so a non-int input
    # already exits 2 with an argparse error before we get here;
    # we still defensively guard against ``bool`` and non-positive
    # values so the CLI matches the Python API's error surface.
    max_len = args.max_len
    if isinstance(max_len, bool) or not isinstance(max_len, int):
        _fail("--max-len must be an int", 2)
    if max_len <= 0:
        _fail("--max-len must be a positive integer", 2)
    text = _read_text_arg(args, attr="file")
    try:
        chunks = chunk_message(text, max_len=max_len)
    except ChunkError as exc:
        _fail(f"chunk failed: {exc}", 3)
    _emit(
        {
            "ok": True,
            "command": "chunk",
            "result": _result_to_dict_chunk(chunks, max_len),
        }
    )


def cmd_sig_shape(args: argparse.Namespace) -> NoReturn:
    # The candidate signature string is read from --value or stdin
    # (the same convention as the ``scan`` and ``chunk`` commands).
    # The validator is a pure function: it does not verify the
    # signature cryptographically, does not sign, POST, or
    # otherwise transmit the value.
    value = getattr(args, "value", None)
    if value is None:
        value = sys.stdin.read()
    elif not isinstance(value, str):
        _fail("--value must be a string", 2)
    # Strip exactly one trailing newline so piping a string into
    # the CLI does not add a bogus 87th character. A pre-existing
    # \n at position 86 (which would never match a canonical
    # signature anyway) still produces a malformed-shape result.
    if value.endswith("\n") and len(value) - 1 == 86:
        value = value[:-1]
    result = validate_signature_shape(value)
    _emit(
        {
            "ok": True,
            "command": "sig-shape",
            "result": _result_to_dict_sig_shape(result),
        }
    )


def cmd_dupe_form(args: argparse.Namespace) -> NoReturn:
    # The text to fold is read from --value or stdin (the same
    # convention as the ``scan``, ``chunk``, and ``sig-shape``
    # commands). The fold is a pure function: it does not sign,
    # POST, fetch, decode, or otherwise transmit the input.
    value = getattr(args, "value", None)
    if value is None:
        value = sys.stdin.read()
    elif not isinstance(value, str):
        _fail("--value must be a string", 2)
    # Strip exactly one trailing newline so piping a string into
    # the CLI does not add a bogus whitespace run at the end. A
    # pre-existing \n in the middle of the input is preserved and
    # folded by the whitespace step.
    if value.endswith("\n") and len(value) >= 1:
        value = value[:-1]
    result = validate_dupe_form(value)
    _emit(
        {
            "ok": True,
            "command": "dupe-form",
            "result": _result_to_dict_dupe_form(result),
        }
    )


def cmd_dupe_exempt(args: argparse.Namespace) -> NoReturn:
    # The text to assess is read from --value or stdin (the
    # same convention as the ``dupe-form`` command). The
    # exemption check is a pure function over its inputs: it
    # does not sign, POST, fetch, decode, or otherwise
    # transmit the text, and it does not read the
    # ``dupe_min_length`` floor from any server. The caller
    # owns the floor; this CLI just enforces the documented
    # rule that "messages shorter than the length floor are
    # exempt".
    value = getattr(args, "value", None)
    if value is None:
        value = sys.stdin.read()
    elif not isinstance(value, str):
        _fail("--value must be a string", 2)
    # Strip exactly one trailing newline so piping a string
    # into the CLI does not add a bogus codepoint that
    # changes the folded length. A pre-existing \n in the
    # middle of the input is preserved and folded by the
    # whitespace step.
    if value.endswith("\n") and len(value) >= 1:
        value = value[:-1]
    # ``--min-length`` is parsed by ``type=int`` so a non-int
    # input already exits 2 with an argparse error before we
    # get here; we still defensively guard against ``bool``
    # and negative values so the CLI matches the Python
    # API's error surface.
    min_length = args.min_length
    if isinstance(min_length, bool) or not isinstance(min_length, int):
        _fail("--min-length must be a non-negative int", 2)
    if min_length < 0:
        _fail("--min-length must be a non-negative int", 2)
    try:
        result = validate_dupe_exempt(value, min_length)
    except TypeError as exc:
        _fail(f"dupe-exempt failed: {exc}", 3)
    except ValueError as exc:
        _fail(f"dupe-exempt failed: {exc}", 3)
    _emit(
        {
            "ok": True,
            "command": "dupe-exempt",
            "result": _result_to_dict_dupe_exempt(result),
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

    p_nonce_safety = sub.add_parser(
        "nonce-safety",
        help=(
            "Structured safety assessment of a nonce string. Reports "
            "shape validity, IEEE 754 double fit, bit length, and "
            "an entropy warning below a caller-supplied bit threshold "
            "(default 32). Pure function; no network I/O."
        ),
    )
    p_nonce_safety.add_argument(
        "--value",
        "-v",
        default=None,
        help=(
            "Nonce string to assess. If omitted, the value is read "
            "from stdin. Exactly one trailing newline is stripped so "
            "piping a value works."
        ),
    )
    p_nonce_safety.add_argument(
        "--min-bits",
        type=int,
        default=NONCE_DEFAULT_MIN_BITS,
        help=(
            "Bit-length threshold below which an entropy_warning "
            "is raised. Must be a positive integer. Defaults to "
            f"{NONCE_DEFAULT_MIN_BITS}."
        ),
    )
    p_nonce_safety.set_defaults(func=cmd_nonce_safety)

    p_chunk = sub.add_parser(
        "chunk",
        help=(
            "Split a text payload into pieces, each no longer than "
            "--max-len codepoints. Useful for posting long messages "
            "that exceed the documented per-message size cap."
        ),
    )
    p_chunk.add_argument(
        "--file",
        "-f",
        default=None,
        help=(
            "Path to a UTF-8 text file. If omitted or set to '-', "
            "the text is read from stdin."
        ),
    )
    p_chunk.add_argument(
        "--max-len",
        type=int,
        default=CHUNKER_DEFAULT_MAX_LEN,
        help=(
            "Maximum chunk length, measured in Python ``len()`` units "
            "(Unicode codepoints). Must be a positive integer. "
            f"Defaults to {CHUNKER_DEFAULT_MAX_LEN}."
        ),
    )
    p_chunk.set_defaults(func=cmd_chunk)

    p_sig_shape = sub.add_parser(
        "sig-shape",
        help=(
            "Validate the surface canonical form of a candidate "
            "Technocore signature (length 86, unpadded base64url, "
            "last char in {A, Q, g, w}). Fast pre-filter; does not "
            "verify the signature cryptographically."
        ),
    )
    p_sig_shape.add_argument(
        "--value",
        "-v",
        default=None,
        help=(
            "Candidate signature string. If omitted, the value is "
            "read from stdin. Exactly one trailing newline is "
            "stripped so piping a value works."
        ),
    )
    p_sig_shape.set_defaults(func=cmd_sig_shape)

    p_dupe_form = sub.add_parser(
        "dupe-form",
        help=(
            "Return the canonical duplicate-filter form of a text "
            "(NFKC + casefold + whitespace fold). The form is the "
            "comparison key the 5-copy 422 counter uses; it is NOT "
            "the signed payload or the stored bytes."
        ),
    )
    p_dupe_form.add_argument(
        "--value",
        "-v",
        default=None,
        help=(
            "Text to fold. If omitted, the value is read from "
            "stdin. Exactly one trailing newline is stripped so "
            "piping a value works."
        ),
    )
    p_dupe_form.set_defaults(func=cmd_dupe_form)

    p_dupe_exempt = sub.add_parser(
        "dupe-exempt",
        help=(
            "Structured verdict of the dupe-filter length-floor "
            "exemption policy. Returns whether the canonical "
            "duplicate-filter form of --value is strictly shorter "
            "than --min-length, the folded form, the folded "
            "length, and the floor the caller supplied. Pure "
            "function; does not read the floor from any server."
        ),
    )
    p_dupe_exempt.add_argument(
        "--value",
        "-v",
        default=None,
        help=(
            "Text to assess. If omitted, the value is read from "
            "stdin. Exactly one trailing newline is stripped so "
            "piping a value works."
        ),
    )
    p_dupe_exempt.add_argument(
        "--min-length",
        type=int,
        required=True,
        help=(
            "Length floor below which the dupe-filter is exempt. "
            "Must be a non-negative integer. The caller owns "
            "this value; this CLI does not read it from any "
            "server. ``0`` disables the floor (every message is "
            "exempt, including the empty string)."
        ),
    )
    p_dupe_exempt.set_defaults(func=cmd_dupe_exempt)

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
