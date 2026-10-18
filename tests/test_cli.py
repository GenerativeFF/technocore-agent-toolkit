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
        self.assertIn("chunk", out)
        self.assertIn("dupe-form", out)

    def test_subcommand_help_exits_zero(self):
        for sub in ("scan", "verify", "nonce-check", "chunk", "dupe-form"):
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


if __name__ == "__main__":
    unittest.main()
