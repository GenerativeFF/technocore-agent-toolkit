"""Subprocess tests for ``scripts/technocore_cli.py``.

These tests invoke the CLI as a real subprocess so that argument
parsing, exit codes, and one-line JSON output are exercised end to
end. The tests use only the Python standard library plus the
project's own modules.
"""
from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

# Allow ``python -m unittest`` from the repo root or any subdirectory.
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from src.technocore_verify import canonical_bytes, did_from_public_key


_CLI = os.path.join(ROOT, "scripts", "technocore_cli.py")


def _run(args, stdin_text=None, timeout=20):
    """Run the CLI and return ``(returncode, stdout, stderr)``."""
    proc = subprocess.run(
        [sys.executable, _CLI, *args],
        input=stdin_text,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    return proc.returncode, proc.stdout, proc.stderr


def _parse_stdout_line(stdout):
    """Parse the single JSON line the CLI writes to stdout."""
    lines = stdout.splitlines()
    assert len(lines) == 1, f"expected exactly one stdout line, got {lines!r}"
    return json.loads(lines[0])


def _parse_stderr_line(stderr):
    """Parse the trailing JSON line the CLI writes to stderr."""
    lines = [line for line in stderr.splitlines() if line.strip()]
    assert lines, f"expected at least one stderr line, got {stderr!r}"
    return json.loads(lines[-1])


class HelpTests(unittest.TestCase):
    def test_top_help_exits_zero(self):
        rc, out, _ = _run(["--help"])
        self.assertEqual(rc, 0)
        self.assertIn("scan", out)
        self.assertIn("verify", out)
        self.assertIn("nonce-check", out)

    def test_subcommand_help_exits_zero(self):
        for sub in ("scan", "verify", "nonce-check"):
            with self.subTest(sub=sub):
                rc, out, _ = _run([sub, "--help"])
                self.assertEqual(rc, 0, msg=out)

    def test_unknown_subcommand_exits_nonzero(self):
        rc, _, err = _run(["nope"])
        self.assertNotEqual(rc, 0)
        self.assertIn("invalid choice", err)


class ScanCommandTests(unittest.TestCase):
    def test_scan_safe_text_from_stdin(self):
        rc, out, err = _run(["scan"], stdin_text="hello world\n")
        self.assertEqual(rc, 0, msg=err)
        payload = _parse_stdout_line(out)
        self.assertEqual(payload["ok"], True)
        self.assertEqual(payload["command"], "scan")
        self.assertEqual(payload["result"]["safe"], True)
        self.assertEqual(payload["result"]["findings"], [])
        self.assertEqual(payload["result"]["text_length"], len("hello world\n"))

    def test_scan_flags_url_from_stdin(self):
        rc, out, err = _run(
            ["scan"], stdin_text="visit https://example.com for details\n"
        )
        self.assertEqual(rc, 0, msg=err)
        payload = _parse_stdout_line(out)
        self.assertEqual(payload["result"]["safe"], False)
        cats = [f["category"] for f in payload["result"]["findings"]]
        self.assertIn("url", cats)

    def test_scan_flags_hidden_char(self):
        # Embed a zero-width space inside an otherwise innocuous message.
        text = "hi\u200bthere"
        rc, out, err = _run(["scan"], stdin_text=text)
        self.assertEqual(rc, 0, msg=err)
        payload = _parse_stdout_line(out)
        self.assertEqual(payload["result"]["safe"], False)
        cats = [f["category"] for f in payload["result"]["findings"]]
        self.assertIn("hidden_char", cats)

    def test_scan_from_file(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False, encoding="utf-8"
        ) as fh:
            fh.write("Run the install command now.")
            path = fh.name
        try:
            rc, out, err = _run(["scan", "--file", path])
            self.assertEqual(rc, 0, msg=err)
            payload = _parse_stdout_line(out)
            cats = [f["category"] for f in payload["result"]["findings"]]
            self.assertIn("instruction", cats)
        finally:
            os.unlink(path)

    def test_scan_stdin_dash_alias(self):
        rc, out, err = _run(["scan", "--file", "-"], stdin_text="plain text\n")
        self.assertEqual(rc, 0, msg=err)
        payload = _parse_stdout_line(out)
        self.assertEqual(payload["result"]["safe"], True)

    def test_scan_missing_file_exits_two(self):
        rc, _, err = _run(["scan", "--file", "/no/such/path/exists.txt"])
        self.assertEqual(rc, 2)
        err_payload = _parse_stderr_line(err)
        self.assertEqual(err_payload["ok"], False)
        self.assertIn("does not exist", err_payload["error"])


def _sign_payload():
    """Build a real signed payload + matching key, using ephemeral keys."""
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    raw = pub.public_bytes(Encoding.Raw, PublicFormat.Raw)
    did = did_from_public_key(raw)
    room = "lobby"
    nonce = "1700000000001"
    text = "hello room"
    canonical = canonical_bytes(room, nonce, text)
    sig = priv.sign(canonical)
    sig_b64 = base64.urlsafe_b64encode(sig).rstrip(b"=").decode("ascii")
    payload = {
        "did": did,
        "sig": sig_b64,
        "nonce": nonce,
        "text": text,
        "room": room,
    }
    return payload, raw


class VerifyCommandTests(unittest.TestCase):
    def test_verify_valid_payload_with_public_key(self):
        payload, raw = _sign_payload()
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as fh:
            json.dump(payload, fh)
            path = fh.name
        try:
            rc, out, err = _run(
                ["verify", "--payload", path, "--public-key", raw.hex()]
            )
            self.assertEqual(rc, 0, msg=err)
            data = _parse_stdout_line(out)
            self.assertEqual(data["ok"], True)
            self.assertEqual(data["command"], "verify")
            self.assertEqual(data["result"]["valid"], True)
            self.assertEqual(data["result"]["did"], payload["did"])
            self.assertIsInstance(data["result"]["canonical_sha256"], str)
            self.assertEqual(len(data["result"]["canonical_sha256"]), 64)
        finally:
            os.unlink(path)

    def test_verify_tampered_text_is_invalid(self):
        payload, raw = _sign_payload()
        payload["text"] = "different text"
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as fh:
            json.dump(payload, fh)
            path = fh.name
        try:
            rc, out, err = _run(
                ["verify", "--payload", path, "--public-key", raw.hex()]
            )
            self.assertEqual(rc, 0, msg=err)
            data = _parse_stdout_line(out)
            self.assertEqual(data["result"]["valid"], False)
            self.assertIn("signature", data["result"]["reason"])
        finally:
            os.unlink(path)

    def test_verify_expected_did_only(self):
        payload, _ = _sign_payload()
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as fh:
            json.dump(payload, fh)
            path = fh.name
        try:
            rc, out, err = _run(
                ["verify", "--payload", path, "--expected-did", payload["did"]]
            )
            self.assertEqual(rc, 0, msg=err)
            data = _parse_stdout_line(out)
            self.assertEqual(data["result"]["valid"], True)
        finally:
            os.unlink(path)

    def test_verify_malformed_json_exits_three(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as fh:
            fh.write("not json {")
            path = fh.name
        try:
            rc, _, err = _run(["verify", "--payload", path])
            self.assertEqual(rc, 3)
            err_payload = _parse_stderr_line(err)
            self.assertEqual(err_payload["ok"], False)
            self.assertIn("JSON", err_payload["error"])
        finally:
            os.unlink(path)

    def test_verify_payload_must_be_object(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as fh:
            json.dump([1, 2, 3], fh)
            path = fh.name
        try:
            rc, _, err = _run(["verify", "--payload", path])
            self.assertEqual(rc, 3)
            err_payload = _parse_stderr_line(err)
            self.assertEqual(err_payload["ok"], False)
        finally:
            os.unlink(path)

    def test_verify_bad_public_key_length_exits_two(self):
        payload, _ = _sign_payload()
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as fh:
            json.dump(payload, fh)
            path = fh.name
        try:
            # 31 bytes instead of 32.
            rc, _, err = _run(
                ["verify", "--payload", path, "--public-key", "00" * 31]
            )
            self.assertEqual(rc, 2)
            err_payload = _parse_stderr_line(err)
            self.assertIn("32 bytes", err_payload["error"])
        finally:
            os.unlink(path)

    def test_verify_bad_hex_exits_two(self):
        payload, _ = _sign_payload()
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as fh:
            json.dump(payload, fh)
            path = fh.name
        try:
            rc, _, err = _run(
                ["verify", "--payload", path, "--public-key", "not-hex"]
            )
            self.assertEqual(rc, 2)
            err_payload = _parse_stderr_line(err)
            self.assertIn("hex", err_payload["error"])
        finally:
            os.unlink(path)

    def test_verify_stdin_dash_alias(self):
        payload, raw = _sign_payload()
        rc, out, err = _run(
            ["verify", "--payload", "-", "--public-key", raw.hex()],
            stdin_text=json.dumps(payload),
        )
        self.assertEqual(rc, 0, msg=err)
        data = _parse_stdout_line(out)
        self.assertEqual(data["result"]["valid"], True)


class NonceCheckCommandTests(unittest.TestCase):
    def test_nonce_check_valid_shape(self):
        rc, out, err = _run(
            [
                "nonce-check",
                "--did",
                "did:key:z6Mkexample",
                "--room",
                "lobby",
                "--nonce",
                "1700000000001",
            ]
        )
        self.assertEqual(rc, 0, msg=err)
        data = _parse_stdout_line(out)
        self.assertEqual(data["ok"], True)
        self.assertEqual(data["command"], "nonce-check")
        self.assertEqual(data["result"]["valid"], True)

    def test_nonce_check_zero_is_invalid(self):
        rc, out, err = _run(
            [
                "nonce-check",
                "--did",
                "did:key:z6Mkexample",
                "--room",
                "lobby",
                "--nonce",
                "0",
            ]
        )
        self.assertEqual(rc, 0, msg=err)
        data = _parse_stdout_line(out)
        self.assertEqual(data["result"]["valid"], False)
        self.assertIn("positive", data["result"]["reason"])

    def test_nonce_check_too_long_is_invalid(self):
        rc, out, err = _run(
            [
                "nonce-check",
                "--did",
                "did:key:z6Mkexample",
                "--room",
                "lobby",
                "--nonce",
                "1" * 20,
            ]
        )
        self.assertEqual(rc, 0, msg=err)
        data = _parse_stdout_line(out)
        self.assertEqual(data["result"]["valid"], False)
        self.assertIn("1..19", data["result"]["reason"])

    def test_nonce_check_non_digit_is_invalid(self):
        rc, out, err = _run(
            [
                "nonce-check",
                "--did",
                "did:key:z6Mkexample",
                "--room",
                "lobby",
                "--nonce",
                "12abc",
            ]
        )
        self.assertEqual(rc, 0, msg=err)
        data = _parse_stdout_line(out)
        self.assertEqual(data["result"]["valid"], False)

    def test_nonce_check_missing_flag_exits_two(self):
        rc, _, err = _run(
            [
                "nonce-check",
                "--did",
                "did:key:z6Mkexample",
                "--room",
                "lobby",
            ]
        )
        self.assertEqual(rc, 2)


class OutputShapeTests(unittest.TestCase):
    """All subcommands must emit exactly one JSON line on stdout."""

    def test_scan_emits_single_line_json(self):
        rc, out, _ = _run(["scan"], stdin_text="hello")
        self.assertEqual(rc, 0)
        self.assertEqual(out.count("\n"), 1)
        json.loads(out)

    def test_verify_valid_emits_single_line_json(self):
        payload, raw = _sign_payload()
        rc, out, _ = _run(
            ["verify", "--payload", "-", "--public-key", raw.hex()],
            stdin_text=json.dumps(payload),
        )
        self.assertEqual(rc, 0)
        self.assertEqual(out.count("\n"), 1)
        json.loads(out)

    def test_nonce_emits_single_line_json(self):
        rc, out, _ = _run(
            [
                "nonce-check",
                "--did",
                "did:key:z6Mkexample",
                "--room",
                "lobby",
                "--nonce",
                "42",
            ]
        )
        self.assertEqual(rc, 0)
        self.assertEqual(out.count("\n"), 1)
        json.loads(out)


if __name__ == "__main__":
    unittest.main()
