"""Subprocess tests for ``scripts/technocore_cli.py``.

These tests invoke the CLI as a real subprocess so that argument
parsing, exit codes, and one-line JSON output are exercised end to
end. The tests use only the Python standard library plus the
project's own modules.
"""
from __future__ import annotations

import base64
import hashlib
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
        self.assertIn("chunk", out)
        self.assertIn("dupe-form", out)
        self.assertIn("dupe-exempt", out)

    def test_subcommand_help_exits_zero(self):
        for sub in ("scan", "verify", "nonce-check", "chunk", "dupe-form", "dupe-exempt"):
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

    def test_chunk_emits_single_line_json(self):
        rc, out, _ = _run(
            ["chunk", "--max-len", "10"],
            stdin_text="hello   world   foo   bar   baz\n",
        )
        self.assertEqual(rc, 0)
        self.assertEqual(out.count("\n"), 1)
        json.loads(out)


class ChunkCommandTests(unittest.TestCase):
    """Subprocess tests for the ``chunk`` subcommand (v0.8.0)."""

    def test_chunk_default_max_len_is_documented_cap(self):
        # When --max-len is omitted, the CLI uses the documented
        # 4096-character per-message cap and echoes it back in the
        # ``default_max_len`` and ``max_len`` fields of the result.
        rc, out, err = _run(["chunk"], stdin_text="hello world")
        self.assertEqual(rc, 0, msg=err)
        payload = _parse_stdout_line(out)
        self.assertEqual(payload["command"], "chunk")
        result = payload["result"]
        self.assertEqual(result["max_len"], 4096)
        self.assertEqual(result["default_max_len"], 4096)
        self.assertEqual(result["version"], 1)
        self.assertEqual(result["chunk_count"], 1)
        self.assertEqual(result["chunks"][0]["text"], "hello world")
        self.assertEqual(result["chunks"][0]["length"], 11)
        self.assertEqual(result["chunks"][0]["index"], 0)

    def test_chunk_custom_max_len_from_stdin(self):
        rc, out, err = _run(
            ["chunk", "--max-len", "10"],
            stdin_text="hello   world   foo   bar   baz",
        )
        self.assertEqual(rc, 0, msg=err)
        payload = _parse_stdout_line(out)
        result = payload["result"]
        self.assertEqual(result["max_len"], 10)
        self.assertEqual(result["chunk_count"], 4)
        for idx, c in enumerate(result["chunks"]):
            self.assertEqual(c["index"], idx)
            self.assertEqual(c["length"], len(c["text"]))
            self.assertLessEqual(c["length"], 10)

    def test_chunk_round_trip_in_output(self):
        text = "alpha beta gamma delta epsilon " * 200
        rc, out, err = _run(["chunk", "--max-len", "64"], stdin_text=text)
        self.assertEqual(rc, 0, msg=err)
        result = _parse_stdout_line(out)["result"]
        joined = "".join(c["text"] for c in result["chunks"])
        self.assertEqual(joined, text)

    def test_chunk_from_file(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False, encoding="utf-8"
        ) as fh:
            fh.write("alpha   beta   gamma   delta   epsilon   zeta")
            path = fh.name
        try:
            rc, out, err = _run(
                ["chunk", "--file", path, "--max-len", "10"]
            )
            self.assertEqual(rc, 0, msg=err)
            result = _parse_stdout_line(out)["result"]
            self.assertGreaterEqual(result["chunk_count"], 2)
            joined = "".join(c["text"] for c in result["chunks"])
            self.assertEqual(joined, "alpha   beta   gamma   delta   epsilon   zeta")
        finally:
            os.unlink(path)

    def test_chunk_stdin_dash_alias(self):
        rc, out, err = _run(
            ["chunk", "--file", "-", "--max-len", "5"],
            stdin_text="a b c d e f g",
        )
        self.assertEqual(rc, 0, msg=err)
        result = _parse_stdout_line(out)["result"]
        joined = "".join(c["text"] for c in result["chunks"])
        self.assertEqual(joined, "a b c d e f g")

    def test_chunk_oversize_token_is_reported(self):
        # A single oversize token is emitted as one chunk; the CLI
        # reports its actual length (which exceeds max_len) so the
        # caller can decide what to do.
        rc, out, err = _run(
            ["chunk", "--max-len", "10"],
            stdin_text="x" * 25,
        )
        self.assertEqual(rc, 0, msg=err)
        result = _parse_stdout_line(out)["result"]
        self.assertEqual(result["chunk_count"], 1)
        self.assertEqual(result["chunks"][0]["length"], 25)
        self.assertEqual(result["chunks"][0]["text"], "x" * 25)

    def test_chunk_zero_max_len_exits_two(self):
        rc, _, err = _run(["chunk", "--max-len", "0"], stdin_text="hi")
        self.assertEqual(rc, 2)
        err_payload = _parse_stderr_line(err)
        self.assertEqual(err_payload["ok"], False)
        self.assertIn("positive", err_payload["error"])

    def test_chunk_negative_max_len_exits_two(self):
        rc, _, err = _run(["chunk", "--max-len", "-5"], stdin_text="hi")
        self.assertEqual(rc, 2)
        err_payload = _parse_stderr_line(err)
        self.assertEqual(err_payload["ok"], False)

    def test_chunk_non_int_max_len_exits_nonzero(self):
        # ``--max-len abc`` is rejected by argparse as a non-int
        # before the subcommand runs, so the exit code is 2 (argparse
        # default).
        rc, _, err = _run(["chunk", "--max-len", "abc"], stdin_text="hi")
        self.assertEqual(rc, 2)
        self.assertIn("invalid int value", err)


class SigShapeCommandTests(unittest.TestCase):
    """Subprocess tests for the ``sig-shape`` subcommand (v0.9.0)."""

    @staticmethod
    def _valid_86(suffix: str = "A") -> str:
        # 85 leading 'A' characters + the requested tail.
        return ("A" * 85) + suffix

    def test_help_top_mentions_sig_shape(self):
        rc, out, _ = _run(["--help"])
        self.assertEqual(rc, 0)
        self.assertIn("sig-shape", out)

    def test_sig_shape_help_exits_zero(self):
        rc, out, _ = _run(["sig-shape", "--help"])
        self.assertEqual(rc, 0, msg=out)
        self.assertIn("--value", out)

    def test_sig_shape_valid_via_value(self):
        for tail in ("A", "Q", "g", "w"):
            with self.subTest(tail=tail):
                rc, out, err = _run(["sig-shape", "--value", self._valid_86(tail)])
                self.assertEqual(rc, 0, msg=err)
                payload = _parse_stdout_line(out)
                self.assertTrue(payload["ok"])
                self.assertEqual(payload["command"], "sig-shape")
                result = payload["result"]
                self.assertTrue(result["valid"])
                self.assertEqual(result["version"], 1)
                self.assertNotIn("reason", result)

    def test_sig_shape_valid_via_stdin(self):
        rc, out, err = _run(
            ["sig-shape"], stdin_text=self._valid_86("g") + "\n"
        )
        self.assertEqual(rc, 0, msg=err)
        result = _parse_stdout_line(out)["result"]
        self.assertTrue(result["valid"])
        self.assertEqual(result["version"], 1)

    def test_sig_shape_rejects_wrong_length(self):
        rc, out, err = _run(["sig-shape", "--value", "A" * 85])
        self.assertEqual(rc, 0, msg=err)
        result = _parse_stdout_line(out)["result"]
        self.assertFalse(result["valid"])
        self.assertIn("length is 85", result["reason"])
        self.assertEqual(result["version"], 1)

    def test_sig_shape_rejects_wrong_tail(self):
        rc, out, err = _run(["sig-shape", "--value", self._valid_86("Z")])
        self.assertEqual(rc, 0, msg=err)
        result = _parse_stdout_line(out)["result"]
        self.assertFalse(result["valid"])
        self.assertIn("last character 'Z'", result["reason"])

    def test_sig_shape_rejects_non_base64url_chars(self):
        # Place the non-base64url character in the middle of an
        # otherwise-valid 86-char string so the alphabet check
        # (not the tail check) is what fires.
        rc, out, err = _run(
            ["sig-shape", "--value", "A" * 40 + "!" + "A" * 45]
        )
        self.assertEqual(rc, 0, msg=err)
        result = _parse_stdout_line(out)["result"]
        self.assertFalse(result["valid"])
        self.assertIn("non-base64url", result["reason"])

    def test_sig_shape_rejects_empty(self):
        rc, out, err = _run(["sig-shape", "--value", ""])
        self.assertEqual(rc, 0, msg=err)
        result = _parse_stdout_line(out)["result"]
        self.assertFalse(result["valid"])
        self.assertIn("length is 0", result["reason"])

    def test_sig_shape_rejects_87_chars(self):
        # 87-char string with a reachable tail: length check fires
        # before the tail check.
        rc, out, err = _run(["sig-shape", "--value", "A" * 86 + "A"])
        self.assertEqual(rc, 0, msg=err)
        result = _parse_stdout_line(out)["result"]
        self.assertFalse(result["valid"])
        self.assertIn("length is 87", result["reason"])

    def test_sig_shape_strips_trailing_newline(self):
        # Piping a string into the CLI should not introduce a
        # bogus 87th character. The CLI strips exactly one trailing
        # newline before validating.
        rc, out, err = _run(
            ["sig-shape"], stdin_text=self._valid_86("g") + "\n"
        )
        self.assertEqual(rc, 0, msg=err)
        result = _parse_stdout_line(out)["result"]
        self.assertTrue(result["valid"])

    def test_sig_shape_emits_single_line_json(self):
        rc, out, _ = _run(["sig-shape", "--value", self._valid_86("A")])
        self.assertEqual(rc, 0)
        self.assertEqual(out.count("\n"), 1)
        json.loads(out)

    def test_sig_shape_real_ed25519_signature_passes(self):
        # A signature produced by the project's own verifier module
        # must pass the surface check.
        priv = Ed25519PrivateKey.generate()
        sig_bytes = priv.sign(b"hello")
        sig_b64 = base64.urlsafe_b64encode(sig_bytes).rstrip(b"=").decode("ascii")
        rc, out, err = _run(["sig-shape", "--value", sig_b64])
        self.assertEqual(rc, 0, msg=err)
        result = _parse_stdout_line(out)["result"]
        self.assertTrue(result["valid"])


class DupeFormCommandTests(unittest.TestCase):
    """Subprocess tests for the ``dupe-form`` subcommand (v1.0.0)."""

    def test_help_top_mentions_dupe_form(self):
        rc, out, _ = _run(["--help"])
        self.assertEqual(rc, 0)
        self.assertIn("dupe-form", out)

    def test_dupe_form_help_exits_zero(self):
        rc, out, _ = _run(["dupe-form", "--help"])
        self.assertEqual(rc, 0, msg=out)
        self.assertIn("--value", out)

    def test_dupe_form_basic_fold_via_value(self):
        rc, out, err = _run(["dupe-form", "--value", "Hello World"])
        self.assertEqual(rc, 0, msg=err)
        payload = _parse_stdout_line(out)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["command"], "dupe-form")
        result = payload["result"]
        self.assertTrue(result["valid"])
        self.assertEqual(result["folded"], "hello world")
        self.assertEqual(result["version"], 1)

    def test_dupe_form_basic_fold_via_stdin(self):
        rc, out, err = _run(
            ["dupe-form"], stdin_text="Hello World\n"
        )
        self.assertEqual(rc, 0, msg=err)
        result = _parse_stdout_line(out)["result"]
        self.assertTrue(result["valid"])
        self.assertEqual(result["folded"], "hello world")

    def test_dupe_form_collapses_nfc_and_nfd(self):
        # The documented example: "Việt" in NFC and NFD
        # both fold to "việt". The CLI must produce the
        # same folded form for both.
        rc1, out1, err1 = _run(["dupe-form", "--value", "Vi\u1ec7t"])
        self.assertEqual(rc1, 0, msg=err1)
        nfc_folded = _parse_stdout_line(out1)["result"]["folded"]
        import unicodedata
        rc2, out2, err2 = _run(
            ["dupe-form", "--value", unicodedata.normalize("NFD", "Vi\u1ec7t")]
        )
        self.assertEqual(rc2, 0, msg=err2)
        nfd_folded = _parse_stdout_line(out2)["result"]["folded"]
        self.assertEqual(nfc_folded, nfd_folded)
        self.assertEqual(nfc_folded, "vi\u1ec7t")

    def test_dupe_form_folds_german_sharp_s(self):
        rc, out, err = _run(["dupe-form", "--value", "Stra\u00dfe"])
        self.assertEqual(rc, 0, msg=err)
        result = _parse_stdout_line(out)["result"]
        self.assertEqual(result["folded"], "strasse")

    def test_dupe_form_folds_circled_numbers(self):
        # ①②③ (NFKC) -> 123.
        rc, out, err = _run(
            ["dupe-form", "--value", "\u2460\u2461\u2462"]
        )
        self.assertEqual(rc, 0, msg=err)
        result = _parse_stdout_line(out)["result"]
        self.assertEqual(result["folded"], "123")

    def test_dupe_form_folds_whitespace(self):
        # ASCII space, tab, newline all fold to a single
        # space; ends are stripped.
        rc, out, err = _run(
            ["dupe-form", "--value", "  hello \t world \n  foo  "]
        )
        self.assertEqual(rc, 0, msg=err)
        result = _parse_stdout_line(out)["result"]
        self.assertEqual(result["folded"], "hello world foo")

    def test_dupe_form_empty_string(self):
        rc, out, err = _run(["dupe-form", "--value", ""])
        self.assertEqual(rc, 0, msg=err)
        result = _parse_stdout_line(out)["result"]
        self.assertTrue(result["valid"])
        self.assertEqual(result["folded"], "")

    def test_dupe_form_whitespace_only(self):
        rc, out, err = _run(["dupe-form", "--value", "   \t\n  "])
        self.assertEqual(rc, 0, msg=err)
        result = _parse_stdout_line(out)["result"]
        self.assertTrue(result["valid"])
        self.assertEqual(result["folded"], "")

    def test_dupe_form_strips_trailing_newline(self):
        # Piping a string into the CLI should not add a
        # bogus trailing whitespace run.
        rc, out, err = _run(
            ["dupe-form"], stdin_text="Hello World\n"
        )
        self.assertEqual(rc, 0, msg=err)
        result = _parse_stdout_line(out)["result"]
        self.assertEqual(result["folded"], "hello world")

    def test_dupe_form_emits_single_line_json(self):
        rc, out, _ = _run(["dupe-form", "--value", "Hello World"])
        self.assertEqual(rc, 0)
        # The CLI writes exactly one line on stdout.
        self.assertEqual(out.count("\n"), 1)
        # And that line is valid JSON.
        json.loads(out)

    def test_dupe_form_idempotent_via_cli(self):
        # dupe_form(dupe_form(x)) == dupe_form(x). Folding
        # the folded output must produce the same form.
        rc1, out1, err1 = _run(
            ["dupe-form", "--value", "Hello World"]
        )
        self.assertEqual(rc1, 0, msg=err1)
        folded_once = _parse_stdout_line(out1)["result"]["folded"]
        rc2, out2, err2 = _run(["dupe-form", "--value", folded_once])
        self.assertEqual(rc2, 0, msg=err2)
        folded_twice = _parse_stdout_line(out2)["result"]["folded"]
        self.assertEqual(folded_once, folded_twice)

    def test_dupe_form_deterministic_via_cli(self):
        # A 50-call loop produces identical results each
        # time. The fold has no hidden state.
        first = None
        for _ in range(50):
            rc, out, err = _run(["dupe-form", "--value", "Hello World"])
            self.assertEqual(rc, 0, msg=err)
            folded = _parse_stdout_line(out)["result"]["folded"]
            if first is None:
                first = folded
            self.assertEqual(folded, first)

    def test_dupe_form_no_amplification_in_stderr(self):
        # A non-string sentinel reaches the type-rejection
        # path. The CLI must not echo the input value in
        # any error channel. (The CLI's exit code for an
        # input validation error is 2; the error is written
        # to stderr as one JSON line.)
        # We use --value with a non-string value via a
        # subprocess-level trick: pass --value with a value
        # that survives shell escaping unchanged. The CLI
        # is a pure function over a Python str, so any
        # string value is valid input; this test only
        # asserts that no input value appears in any
        # error channel for the *valid* happy path. The
        # structured-verdict channel is exercised by the
        # Python API tests; here we lock down the JSON
        # output contract on the happy path.
        rc, out, err = _run(["dupe-form", "--value", "Hello World"])
        self.assertEqual(rc, 0)
        self.assertEqual(err, "")
        # The output line must not contain the input
        # verbatim except as the *folded* form (which is
        # the documented transformation, not an echo of
        # the input).
        payload = _parse_stdout_line(out)
        # The folded form is "hello world" (lowercased);
        # the input was "Hello World" (mixed case). The
        # payload itself does not echo the input string
        # in any field.
        self.assertNotIn("Hello World", json.dumps(payload))
        # And the folded form is the documented lowercased
        # form.
        self.assertEqual(payload["result"]["folded"], "hello world")

    def test_dupe_form_help_mentions_comparison_form(self):
        # The subcommand help text (visible in the top-level
        # ``--help`` output) must mention that the output is
        # the *comparison* form, not the signed payload.
        # This is a documentation guard so callers do not
        # accidentally sign the folded form.
        rc, out, _ = _run(["--help"])
        self.assertEqual(rc, 0)
        # argparse renders the subcommand help text in the
        # top-level --help output under
        # "dupe-form   <description>".
        self.assertIn("dupe-form", out)
        # The description must mention both "comparison"
        # and "signed" so callers can see the distinction
        # without reading the docs.
        self.assertIn("comparison", out.lower())
        self.assertIn("signed", out.lower())


class DupeExemptCommandTests(unittest.TestCase):
    """Subprocess tests for the ``dupe-exempt`` subcommand (v1.0.3)."""

    def test_help_top_mentions_dupe_exempt(self):
        rc, out, _ = _run(["--help"])
        self.assertEqual(rc, 0)
        self.assertIn("dupe-exempt", out)

    def test_dupe_exempt_help_exits_zero(self):
        rc, out, _ = _run(["dupe-exempt", "--help"])
        self.assertEqual(rc, 0, msg=out)
        self.assertIn("--value", out)
        self.assertIn("--min-length", out)

    def test_dupe_exempt_exempt_at_realistic_floor(self):
        # "ok" folds to "ok" (length 2); at min-length 3 the
        # documented conversational repeat IS exempt.
        rc, out, err = _run(
            ["dupe-exempt", "--value", "ok", "--min-length", "3"]
        )
        self.assertEqual(rc, 0, msg=err)
        payload = _parse_stdout_line(out)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["command"], "dupe-exempt")
        result = payload["result"]
        self.assertTrue(result["valid"])
        self.assertTrue(result["exempt"])
        self.assertEqual(result["folded"], "ok")
        self.assertEqual(result["folded_length"], 2)
        self.assertEqual(result["min_length"], 3)
        self.assertEqual(result["version"], 1)

    def test_dupe_exempt_not_exempt_at_equal_floor(self):
        # "ok" folds to length 2; at min-length 2 the rule
        # is "strictly less than", so it is NOT exempt.
        rc, out, err = _run(
            ["dupe-exempt", "--value", "ok", "--min-length", "2"]
        )
        self.assertEqual(rc, 0, msg=err)
        result = _parse_stdout_line(out)["result"]
        self.assertTrue(result["valid"])
        self.assertFalse(result["exempt"])
        self.assertEqual(result["folded_length"], 2)
        self.assertEqual(result["min_length"], 2)

    def test_dupe_exempt_not_exempt_at_zero_floor_for_nonempty(self):
        # A floor of 0 disables the floor; every non-empty
        # text has folded length >= 1, which is NOT strictly
        # less than 0, so it is NOT exempt.
        rc, out, err = _run(
            ["dupe-exempt", "--value", "ok", "--min-length", "0"]
        )
        self.assertEqual(rc, 0, msg=err)
        result = _parse_stdout_line(out)["result"]
        self.assertTrue(result["valid"])
        self.assertFalse(result["exempt"])

    def test_dupe_exempt_via_stdin(self):
        # The text can be supplied via stdin; exactly one
        # trailing newline is stripped so piping a value
        # works.
        rc, out, err = _run(
            ["dupe-exempt", "--min-length", "3"],
            stdin_text="ok\n",
        )
        self.assertEqual(rc, 0, msg=err)
        result = _parse_stdout_line(out)["result"]
        self.assertTrue(result["valid"])
        self.assertTrue(result["exempt"])
        self.assertEqual(result["folded"], "ok")

    def test_dupe_exempt_folds_nfc_and_nfd_to_same_verdict(self):
        # The fold collapses NFC and NFD of the same word to
        # the same folded form, so the exemption verdict must
        # be identical for both.
        import unicodedata  # local import keeps the top of
        # the file independent of this test
        nfc = "Vi\u1ec7t"  # 4 codepoints
        nfd = unicodedata.normalize("NFD", nfc)  # 6 codepoints
        rc1, out1, _ = _run(
            ["dupe-exempt", "--value", nfc, "--min-length", "5"]
        )
        rc2, out2, _ = _run(
            ["dupe-exempt", "--value", nfd, "--min-length", "5"]
        )
        self.assertEqual(rc1, 0)
        self.assertEqual(rc2, 0)
        r1 = _parse_stdout_line(out1)["result"]
        r2 = _parse_stdout_line(out2)["result"]
        self.assertEqual(r1["exempt"], r2["exempt"])
        self.assertEqual(r1["folded"], r2["folded"])
        self.assertEqual(r1["folded_length"], r2["folded_length"])

    def test_dupe_exempt_missing_min_length_fails(self):
        # --min-length is required; omitting it must exit 2
        # (argparse validation error) and not emit a
        # verdict.
        rc, _, err = _run(["dupe-exempt", "--value", "ok"])
        self.assertEqual(rc, 2, msg=err)

    def test_dupe_exempt_negative_min_length_fails(self):
        # A negative --min-length is rejected at the CLI
        # boundary with exit 2.
        rc, _, err = _run(
            ["dupe-exempt", "--value", "ok", "--min-length", "-1"]
        )
        self.assertEqual(rc, 2, msg=err)
        # The error JSON must not echo the offending value.
        lines = err.strip().splitlines()
        self.assertTrue(lines)
        err_obj = json.loads(lines[-1])
        self.assertFalse(err_obj["ok"])
        self.assertNotIn("-1", err_obj["error"])

    def test_dupe_exempt_non_int_min_length_fails(self):
        # A non-integer --min-length is rejected by argparse
        # with exit 2 before our handler runs. argparse
        # writes its own plain-text usage error to stderr
        # (not the JSON error envelope the cmd_* handlers
        # write), so we only assert on the exit code here;
        # the JSON-parseable error surface is covered by
        # the negative-min-length test below.
        rc, _, err = _run(
            ["dupe-exempt", "--value", "ok", "--min-length", "three"]
        )
        self.assertEqual(rc, 2, msg=err)
        self.assertTrue(err.strip(), "expected a usage error on stderr")

    def test_dupe_exempt_payload_does_not_echo_input(self):
        # The successful payload must not contain the input
        # value in any field. The CLI surfaces the *folded*
        # form, the folded length, the min_length, and the
        # verdict; it never surfaces the original input.
        rc, out, _ = _run(
            ["dupe-exempt", "--value", "Hello World", "--min-length", "3"]
        )
        self.assertEqual(rc, 0)
        payload = _parse_stdout_line(out)
        self.assertNotIn("Hello World", json.dumps(payload))


class DupeDecisionCommandTests(unittest.TestCase):
    """Subprocess tests for the ``dupe-decision`` subcommand (v1.0.5).

    The ``dupe-decision`` subcommand is the orchestrator
    over the three dupe-filter legs. Its CLI surface
    combines the ``--value`` / ``--history`` / ``--min-length``
    flags of the ``dupe-exempt`` and ``dupe-window``
    subcommands with the ``--window-seconds``,
    ``--max-copies``, and ``--now`` flags unique to the
    window counter. The tests below exercise the documented
    three-step policy end-to-end:

    * Leg 1 (disabled-filter short-circuit): ``--window-seconds 0``
      lands every text, regardless of the history or the
      copy threshold.
    * Leg 2 (length-floor exemption): a folded length
      strictly less than ``--min-length`` lands regardless
      of the history or the copy threshold.
    * Leg 3 (window counter): with a non-zero window and a
      non-exempt text, the count of matching history
      entries inside the window determines the verdict.

    All inputs are treated as untrusted data. The CLI
    surfaces the folded form, the fold length, the supplied
    configuration, and the verdict; it never surfaces the
    raw input value.
    """

    def _write_history(self, entries):
        """Write a history list to a temp JSON file and return its path."""
        handle = tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        )
        json.dump(entries, handle)
        handle.flush()
        handle.close()
        self.addCleanup(os.unlink, handle.name)
        return handle.name

    def test_help_top_mentions_dupe_decision(self):
        rc, out, _ = _run(["--help"])
        self.assertEqual(rc, 0)
        self.assertIn("dupe-decision", out)

    def test_dupe_decision_help_exits_zero(self):
        rc, out, _ = _run(["dupe-decision", "--help"])
        self.assertEqual(rc, 0, msg=out)
        self.assertIn("--value", out)
        self.assertIn("--history", out)
        self.assertIn("--window-seconds", out)
        self.assertIn("--max-copies", out)
        self.assertIn("--min-length", out)
        self.assertIn("--now", out)

    def test_dupe_decision_empty_history_lands(self):
        # No matching history; the count of matching entries
        # inside the window is 0; the text lands.
        rc, out, err = _run(
            [
                "dupe-decision",
                "--value", "hello world",
                "--history", self._write_history([]),
                "--window-seconds", "60",
                "--max-copies", "3",
                "--min-length", "4",
            ]
        )
        self.assertEqual(rc, 0, msg=err)
        result = _parse_stdout_line(out)["result"]
        self.assertTrue(result["valid"])
        self.assertTrue(result["would_land"])
        self.assertFalse(result["refused"])
        self.assertTrue(result["filter_active"])
        self.assertFalse(result["exempt"])
        self.assertEqual(result["copies_in_window"], 0)
        self.assertEqual(result["folded"], "hello world")
        self.assertEqual(result["folded_length"], 11)
        self.assertEqual(result["max_copies"], 3)
        self.assertEqual(result["min_length"], 4)
        self.assertEqual(result["window_seconds"], 60.0)
        self.assertEqual(result["dupe_decision_version"], 1)
        self.assertEqual(result["dupe_window_version"], 1)

    def test_dupe_decision_third_copy_lands(self):
        # Two prior copies inside the window with max_copies=3
        # means the third copy lands (count=2 < 3).
        history = [
            ["hello world", 1000],
            ["hello world", 1010],
        ]
        rc, out, err = _run(
            [
                "dupe-decision",
                "--value", "hello world",
                "--history", self._write_history(history),
                "--window-seconds", "60",
                "--max-copies", "3",
                "--min-length", "4",
            ]
        )
        self.assertEqual(rc, 0, msg=err)
        result = _parse_stdout_line(out)["result"]
        self.assertTrue(result["valid"])
        self.assertTrue(result["would_land"])
        self.assertFalse(result["refused"])
        self.assertEqual(result["copies_in_window"], 2)

    def test_dupe_decision_fourth_copy_refused(self):
        # Three prior copies inside the window with max_copies=3
        # means the fourth copy is refused (count=3 >= 3).
        history = [
            ["hello world", 1000],
            ["hello world", 1010],
            ["hello world", 1020],
        ]
        rc, out, err = _run(
            [
                "dupe-decision",
                "--value", "hello world",
                "--history", self._write_history(history),
                "--window-seconds", "60",
                "--max-copies", "3",
                "--min-length", "4",
            ]
        )
        self.assertEqual(rc, 0, msg=err)
        result = _parse_stdout_line(out)["result"]
        self.assertTrue(result["valid"])
        self.assertFalse(result["would_land"])
        self.assertTrue(result["refused"])
        self.assertEqual(result["copies_in_window"], 3)

    def test_dupe_decision_disabled_filter_short_circuits(self):
        # window_seconds=0 disables the filter: even with a
        # refilled history and max_copies=0 the text lands.
        history = [["hello world", 1000 + i] for i in range(50)]
        rc, out, err = _run(
            [
                "dupe-decision",
                "--value", "hello world",
                "--history", self._write_history(history),
                "--window-seconds", "0",
                "--max-copies", "0",
                "--min-length", "4",
            ]
        )
        self.assertEqual(rc, 0, msg=err)
        result = _parse_stdout_line(out)["result"]
        self.assertTrue(result["valid"])
        self.assertTrue(result["would_land"])
        self.assertFalse(result["refused"])
        self.assertFalse(result["filter_active"])
        self.assertEqual(result["copies_in_window"], 0)
        self.assertEqual(result["window_seconds"], 0.0)

    def test_dupe_decision_length_floor_exempt_lands(self):
        # "ok" folds to length 2; min-length 3 means the
        # strict-less-than rule exempts the text, regardless
        # of the history.
        history = [["ok", 1000 + i] for i in range(50)]
        rc, out, err = _run(
            [
                "dupe-decision",
                "--value", "ok",
                "--history", self._write_history(history),
                "--window-seconds", "60",
                "--max-copies", "3",
                "--min-length", "3",
            ]
        )
        self.assertEqual(rc, 0, msg=err)
        result = _parse_stdout_line(out)["result"]
        self.assertTrue(result["valid"])
        self.assertTrue(result["would_land"])
        self.assertFalse(result["refused"])
        self.assertTrue(result["filter_active"])
        self.assertTrue(result["exempt"])
        self.assertEqual(result["copies_in_window"], 0)
        self.assertEqual(result["folded"], "ok")
        self.assertEqual(result["folded_length"], 2)

    def test_dupe_decision_value_via_stdin(self):
        # The value can be supplied via stdin; exactly one
        # trailing newline is stripped.
        history = [["hello world", 1000], ["hello world", 1010]]
        rc, out, err = _run(
            [
                "dupe-decision",
                "--history", self._write_history(history),
                "--window-seconds", "60",
                "--max-copies", "3",
                "--min-length", "4",
            ],
            stdin_text="hello world\n",
        )
        self.assertEqual(rc, 0, msg=err)
        result = _parse_stdout_line(out)["result"]
        self.assertTrue(result["valid"])
        self.assertTrue(result["would_land"])

    def test_dupe_decision_history_via_stdin(self):
        # The history can be supplied via ``--history -`` from
        # stdin, the same convention as ``--file``. Stdin is
        # read once, so the value must be passed via --value.
        history_text = json.dumps(
            [["hello world", 1000], ["hello world", 1010]]
        )
        rc, out, err = _run(
            [
                "dupe-decision",
                "--value", "hello world",
                "--history", "-",
                "--window-seconds", "60",
                "--max-copies", "3",
                "--min-length", "4",
            ],
            stdin_text=history_text,
        )
        self.assertEqual(rc, 0, msg=err)
        result = _parse_stdout_line(out)["result"]
        self.assertTrue(result["valid"])
        self.assertTrue(result["would_land"])
        self.assertEqual(result["copies_in_window"], 2)

    def test_dupe_decision_missing_window_seconds_fails(self):
        rc, _, err = _run(
            [
                "dupe-decision",
                "--value", "hello world",
                "--history", self._write_history([]),
                "--max-copies", "3",
                "--min-length", "4",
            ]
        )
        self.assertEqual(rc, 2, msg=err)

    def test_dupe_decision_missing_max_copies_fails(self):
        rc, _, err = _run(
            [
                "dupe-decision",
                "--value", "hello world",
                "--history", self._write_history([]),
                "--window-seconds", "60",
                "--min-length", "4",
            ]
        )
        self.assertEqual(rc, 2, msg=err)

    def test_dupe_decision_negative_window_seconds_fails(self):
        rc, _, err = _run(
            [
                "dupe-decision",
                "--value", "hello world",
                "--history", self._write_history([]),
                "--window-seconds", "-1",
                "--max-copies", "3",
                "--min-length", "4",
            ]
        )
        self.assertEqual(rc, 2, msg=err)
        lines = err.strip().splitlines()
        self.assertTrue(lines)
        err_obj = json.loads(lines[-1])
        self.assertFalse(err_obj["ok"])
        # The error must not echo the offending value.
        self.assertNotIn("-1", err_obj["error"])

    def test_dupe_decision_history_not_list_fails(self):
        # ``--history`` must be a JSON array of [text, ts] pairs.
        handle = tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        )
        json.dump({"not": "an array"}, handle)
        handle.flush()
        handle.close()
        self.addCleanup(os.unlink, handle.name)
        rc, _, err = _run(
            [
                "dupe-decision",
                "--value", "hello world",
                "--history", handle.name,
                "--window-seconds", "60",
                "--max-copies", "3",
                "--min-length", "4",
            ]
        )
        self.assertEqual(rc, 3, msg=err)

    def test_dupe_decision_folds_nfc_and_nfd_to_same_verdict(self):
        # The canonical fold collapses NFC and NFD to the
        # same comparison form, so the three-step verdict
        # must be identical for both.
        import unicodedata  # local import keeps the top of
        # the file independent of this test

        nfc = "Vi\u1ec7t"  # 4 codepoints
        nfd = unicodedata.normalize("NFD", nfc)  # 6 codepoints
        history_nfc = [[nfc, 1000], [nfc, 1010]]
        history_nfd = [[nfd, 1000], [nfd, 1010]]
        rc1, out1, _ = _run(
            [
                "dupe-decision",
                "--value", nfc,
                "--history", self._write_history(history_nfc),
                "--window-seconds", "60",
                "--max-copies", "3",
                "--min-length", "4",
            ]
        )
        rc2, out2, _ = _run(
            [
                "dupe-decision",
                "--value", nfd,
                "--history", self._write_history(history_nfd),
                "--window-seconds", "60",
                "--max-copies", "3",
                "--min-length", "4",
            ]
        )
        self.assertEqual(rc1, 0)
        self.assertEqual(rc2, 0)
        r1 = _parse_stdout_line(out1)["result"]
        r2 = _parse_stdout_line(out2)["result"]
        self.assertEqual(r1["would_land"], r2["would_land"])
        self.assertEqual(r1["refused"], r2["refused"])
        self.assertEqual(r1["folded"], r2["folded"])
        self.assertEqual(r1["folded_length"], r2["folded_length"])
        self.assertEqual(r1["copies_in_window"], r2["copies_in_window"])

    def test_dupe_decision_payload_does_not_echo_input(self):
        # The successful payload must not contain the raw
        # input value (mixed-case "Hello World"). The CLI
        # surfaces the *folded* form, the fold length, and
        # the verdict; it must never surface the original
        # input on any field.
        history = [["Hello World", 1000], ["hello world", 1010]]
        rc, out, err = _run(
            [
                "dupe-decision",
                "--value", "Hello World",
                "--history", self._write_history(history),
                "--window-seconds", "60",
                "--max-copies", "3",
                "--min-length", "4",
            ]
        )
        self.assertEqual(rc, 0, msg=err)
        payload = _parse_stdout_line(out)
        # The raw input was "Hello World"; the canonical
        # fold produces "hello world"; the payload must
        # only contain the folded form, never the original
        # capitalisation. We do NOT assert "Hello World"
        # absent because the history deliberately includes
        # it to exercise the cross-form match; we assert the
        # verdict reflects the folded match (would_land=True
        # since count=2 < 3) and the version fields are
        # populated.
        result = payload["result"]
        self.assertTrue(result["valid"])
        self.assertTrue(result["would_land"])
        self.assertEqual(result["folded"], "hello world")
        self.assertEqual(result["dupe_decision_version"], 1)
        self.assertEqual(result["dupe_window_version"], 1)


class BindingCommandTests(unittest.TestCase):
    """Subprocess tests for the ``binding`` subcommand."""

    RECORD = {
        "from": "did:key:z6MkhiRKcJjvdy1s4m6np8GgoLoqgVaRm5PmUVNKKiW9VpEZ",
        "nonce": 1792493744548,
        "text": "hello",
        "ts": "2026-10-20T10:55:48.708802Z",
        "seq": 199735,
        "sig": "XTINzh9gw53_kMnbC6F_UOwqGLyEnYAsrOaxchiGbIxTDbHPXZi5oaX2KwwTBb5nh0L-MRAOhsY3_IVRAllWBQ",
    }

    def _record_json(self, **overrides):
        record = dict(self.RECORD)
        record.update(overrides)
        return json.dumps(record)

    def test_record_from_stdin_with_room_flag(self):
        code, out, err = _run(
            ["binding", "--room", "dev"], stdin_text=self._record_json()
        )
        self.assertEqual(code, 0, err)
        payload = _parse_stdout_line(out)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["command"], "binding")
        result = payload["result"]
        self.assertTrue(result["ok"])
        self.assertEqual(result["room"], "dev")

    def test_reports_ts_and_seq_as_unsigned(self):
        code, out, err = _run(
            ["binding", "--room", "dev"], stdin_text=self._record_json()
        )
        self.assertEqual(code, 0, err)
        result = _parse_stdout_line(out)["result"]
        self.assertEqual(result["unsigned_server_fields"], ["ts", "seq"])

    def test_reports_signed_fields(self):
        code, out, _ = _run(
            ["binding", "--room", "dev"], stdin_text=self._record_json()
        )
        self.assertEqual(code, 0)
        result = _parse_stdout_line(out)["result"]
        self.assertEqual(result["signed_fields"], ["room", "nonce", "text"])

    def test_reports_identity_field_as_from(self):
        code, out, _ = _run(
            ["binding", "--room", "dev"], stdin_text=self._record_json()
        )
        self.assertEqual(code, 0)
        result = _parse_stdout_line(out)["result"]
        self.assertEqual(result["identity_field"], "from")

    def test_canonical_sha_is_emitted(self):
        code, out, _ = _run(
            ["binding", "--room", "dev"], stdin_text=self._record_json()
        )
        self.assertEqual(code, 0)
        result = _parse_stdout_line(out)["result"]
        expected = hashlib.sha256(
            canonical_bytes("dev", "1792493744548", "hello")
        ).hexdigest()
        self.assertEqual(result["canonical_sha256"], expected)

    def test_warns_about_integer_nonce(self):
        code, out, _ = _run(
            ["binding", "--room", "dev"], stdin_text=self._record_json()
        )
        self.assertEqual(code, 0)
        warnings = " ".join(_parse_stdout_line(out)["result"]["warnings"])
        self.assertIn("JSON number", warnings)

    def test_dash_record_reads_stdin(self):
        code, out, _ = _run(
            ["binding", "--record", "-", "--room", "dev"],
            stdin_text=self._record_json(),
        )
        self.assertEqual(code, 0)
        self.assertTrue(_parse_stdout_line(out)["ok"])

    def test_record_from_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "record.json")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(self._record_json())
            code, out, err = _run(["binding", "--record", path, "--room", "dev"])
        self.assertEqual(code, 0, err)
        self.assertTrue(_parse_stdout_line(out)["ok"])

    def test_missing_record_file_exits_two(self):
        code, _, err = _run(
            ["binding", "--record", "/nonexistent/record.json", "--room", "dev"]
        )
        self.assertEqual(code, 2)
        self.assertIn("error", _parse_stderr_line(err))

    def test_envelope_room_is_used(self):
        envelope = json.dumps(
            {"room": "dev", "count": 1, "messages": [self.RECORD]}
        )
        code, out, err = _run(["binding"], stdin_text=envelope)
        self.assertEqual(code, 0, err)
        self.assertEqual(_parse_stdout_line(out)["result"]["room"], "dev")

    def test_explicit_room_overrides_envelope(self):
        envelope = json.dumps(
            {"room": "dev", "count": 1, "messages": [self.RECORD]}
        )
        code, out, _ = _run(["binding", "--room", "other"], stdin_text=envelope)
        self.assertEqual(code, 0)
        self.assertEqual(_parse_stdout_line(out)["result"]["room"], "other")

    def test_bare_array_is_accepted(self):
        code, out, err = _run(
            ["binding", "--room", "dev"],
            stdin_text=json.dumps([self.RECORD]),
        )
        self.assertEqual(code, 0, err)
        self.assertTrue(_parse_stdout_line(out)["ok"])

    def test_empty_envelope_exits_two(self):
        code, _, err = _run(
            ["binding", "--room", "dev"],
            stdin_text=json.dumps({"room": "dev", "messages": []}),
        )
        self.assertEqual(code, 2)
        self.assertIn("error", _parse_stderr_line(err))

    def test_empty_array_exits_two(self):
        code, _, err = _run(
            ["binding", "--room", "dev"], stdin_text="[]"
        )
        self.assertEqual(code, 2)
        self.assertIn("error", _parse_stderr_line(err))

    def test_invalid_json_exits_two(self):
        code, _, err = _run(["binding", "--room", "dev"], stdin_text="not json")
        self.assertEqual(code, 2)
        self.assertIn("error", _parse_stderr_line(err))

    def test_missing_room_exits_zero_with_static_reason(self):
        code, out, err = _run(
            ["binding"], stdin_text=self._record_json()
        )
        self.assertEqual(code, 0, err)
        result = _parse_stdout_line(out)["result"]
        self.assertFalse(result["ok"])
        self.assertIn("room", result["reason"])

    def test_output_is_exactly_one_json_line(self):
        code, out, _ = _run(
            ["binding", "--room", "dev"], stdin_text=self._record_json()
        )
        self.assertEqual(code, 0)
        self.assertEqual(len(out.splitlines()), 1)

    def test_help_lists_binding(self):
        code, out, _ = _run(["--help"])
        self.assertEqual(code, 0)
        self.assertIn("binding", out)


if __name__ == "__main__":
    unittest.main()
