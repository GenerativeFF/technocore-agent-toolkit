"""Unit tests for ``technocore_scanner``.

The scanner is a pure function over a string. Tests cover:

* clean text returns ``safe=True`` with no findings;
* each detection category fires on a representative input;
* severity ordering (``safe`` is ``False`` whenever a ``warn`` or
  ``high`` finding is produced);
* the scanner is deterministic — identical input produces identical
  output;
* the scanner raises ``ScanError`` on non-string input;
* ``evidence`` excerpts are always ``<= _MAX_EVIDENCE`` (40) characters;
* the scanner does *not* echo full URLs, paths, or blobs.

No network I/O, no subprocess, no decoding.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src.technocore_scanner import (  # noqa: E402
    ScanError,
    ScanFinding,
    ScanResult,
    _MAX_EVIDENCE,
    scan,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _categories(result: ScanResult) -> set:
    return {f.category for f in result.findings}


def _evidences(result: ScanResult) -> list:
    return [f.evidence for f in result.findings]


# ---------------------------------------------------------------------------
# Happy-path tests
# ---------------------------------------------------------------------------


class CleanTextTests(unittest.TestCase):
    """Clean, prose-only text must come back ``safe=True``."""

    def test_empty_string(self):
        r = scan("")
        self.assertTrue(r.safe)
        self.assertEqual(r.findings, ())
        self.assertEqual(r.text_length, 0)

    def test_greeting(self):
        r = scan("hello everyone, glad to be here")
        self.assertTrue(r.safe, msg=f"findings={r.findings}")
        self.assertEqual(r.findings, ())

    def test_prose_with_punctuation(self):
        r = scan(
            "This is a normal message. It has sentences, "
            "commas, and even a question? Yes!"
        )
        self.assertTrue(r.safe, msg=f"findings={r.findings}")
        self.assertEqual(r.findings, ())

    def test_prose_with_numbers(self):
        r = scan("Counts: 1, 2, 3. Ratios: 1.5 to 2.0. Hash: 0xdeadbeef is fine.")
        # 0xdeadbeef is too short for the hex-blob detector (10 chars).
        self.assertTrue(r.safe, msg=f"findings={r.findings}")

    def test_prose_with_quoted_phrase(self):
        # Double-quoted text containing shell-like words should not flag
        # on its own.
        r = scan('She said "please run the tests" but in scare quotes.')
        # "please run" at the start of the quoted phrase won't match
        # because we require a sentence terminator or line start before
        # the verb. The bare word "tests" is fine.
        self.assertTrue(r.safe, msg=f"findings={r.findings}")


# ---------------------------------------------------------------------------
# Per-category detection tests
# ---------------------------------------------------------------------------


class PathDetectionTests(unittest.TestCase):
    def test_unix_absolute_path(self):
        r = scan("Check /etc/passwd for the file")
        self.assertFalse(r.safe)
        self.assertIn("path", _categories(r))

    def test_home_relative_path(self):
        r = scan("See ~/Projects/foo for details")
        self.assertFalse(r.safe)
        self.assertIn("path", _categories(r))

    def test_dot_relative_path(self):
        r = scan("Try ./scripts/run.sh to start")
        self.assertFalse(r.safe)
        # Both path and shell could match; we only assert at least path.
        self.assertIn("path", _categories(r))

    def test_windows_path(self):
        r = scan("Open C:\\Users\\Alice\\file.txt now")
        self.assertFalse(r.safe)
        self.assertIn("path", _categories(r))

    def test_path_evidence_is_truncated(self):
        long_path = "/" + "a" * 80 + "/b"
        r = scan(f"please look at {long_path}")
        paths = [f for f in r.findings if f.category == "path"]
        self.assertTrue(paths)
        for f in paths:
            self.assertLessEqual(len(f.evidence), _MAX_EVIDENCE)


class UrlDetectionTests(unittest.TestCase):
    def test_https_url(self):
        r = scan("Read https://example.com/docs for the spec")
        self.assertFalse(r.safe)
        self.assertIn("url", _categories(r))

    def test_http_url(self):
        r = scan("Visit http://attacker.example/payload now")
        self.assertFalse(r.safe)
        self.assertIn("url", _categories(r))

    def test_bare_www_host(self):
        r = scan("See www.example.com for more info")
        self.assertFalse(r.safe)
        self.assertIn("url", _categories(r))

    def test_url_evidence_is_truncated(self):
        long = "https://example.com/" + "a" * 100
        r = scan(f"check {long} please")
        urls = [f for f in r.findings if f.category == "url"]
        self.assertTrue(urls)
        for f in urls:
            self.assertLessEqual(len(f.evidence), _MAX_EVIDENCE)
            # The full URL must never appear verbatim in any evidence.
            self.assertNotIn(long, f.evidence)


class ShellDetectionTests(unittest.TestCase):
    def test_backtick_command(self):
        r = scan("Try this: `rm -rf /tmp/foo` to clean up")
        self.assertFalse(r.safe)
        self.assertIn("shell", _categories(r))

    def test_dollar_paren_command_substitution(self):
        r = scan("Output is $(cat /etc/secret)")
        self.assertFalse(r.safe)
        self.assertIn("shell", _categories(r))

    def test_double_amp_chain(self):
        r = scan("first && second")
        self.assertFalse(r.safe)
        self.assertIn("shell", _categories(r))

    def test_double_pipe_chain(self):
        r = scan("first || second")
        self.assertFalse(r.safe)
        self.assertIn("shell", _categories(r))

    def test_shell_evidence_does_not_echo_full_command(self):
        # The full ``rm -rf /tmp/foo`` should never appear verbatim.
        long_cmd = "`" + ("echo " * 30) + "/tmp/foo`"
        r = scan(f"Try this: {long_cmd}")
        shells = [f for f in r.findings if f.category == "shell"]
        self.assertTrue(shells)
        for f in shells:
            self.assertLessEqual(len(f.evidence), _MAX_EVIDENCE)
            self.assertNotIn(long_cmd, f.evidence)


class InstructionDetectionTests(unittest.TestCase):
    def test_run_after_period(self):
        r = scan("Important. Run the deploy script now.")
        self.assertFalse(r.safe)
        self.assertIn("instruction", _categories(r))

    def test_install_after_newline(self):
        r = scan("First we test.\nNow install the package.")
        self.assertFalse(r.safe)
        self.assertIn("instruction", _categories(r))

    def test_please_run_at_start(self):
        r = scan("Please run the unit tests before merging.")
        self.assertFalse(r.safe)
        self.assertIn("instruction", _categories(r))

    def test_no_instruction_in_mid_sentence(self):
        # The verb "run" appearing mid-sentence without a sentence
        # terminator before it should not match.
        r = scan("The tests run quickly on this machine.")
        # Even if other categories fire, instruction must not.
        for f in r.findings:
            self.assertNotEqual(f.category, "instruction")


class CodeBlockDetectionTests(unittest.TestCase):
    def test_fenced_code_block(self):
        r = scan("Here is some code:\n```\nrm -rf /\n```")
        self.assertFalse(r.safe)
        self.assertIn("code_block", _categories(r))
        # Fenced block must be warn, not info.
        for f in r.findings:
            if f.category == "code_block":
                self.assertEqual(f.severity, "warn")

    def test_indented_block_is_info_only(self):
        r = scan("Try this:\n    rm -rf /\n    echo done")
        # Indented-only block should be at info severity, leaving
        # ``safe`` True if it is the only finding.
        code_findings = [f for f in r.findings if f.category == "code_block"]
        self.assertTrue(code_findings)
        for f in code_findings:
            self.assertEqual(f.severity, "info")
        # ``shell`` is also likely to fire from the rm; we only assert
        # that there is at least one info finding.
        self.assertTrue(any(f.severity == "info" for f in r.findings))


class HiddenCharDetectionTests(unittest.TestCase):
    def test_zero_width_space(self):
        r = scan("hello\u200bworld")
        self.assertFalse(r.safe)
        self.assertIn("hidden_char", _categories(r))

    def test_rtl_override(self):
        r = scan("filename\u202egpj.exe")
        self.assertFalse(r.safe)
        self.assertIn("hidden_char", _categories(r))

    def test_bom(self):
        r = scan("\ufeffstart of file")
        self.assertFalse(r.safe)
        self.assertIn("hidden_char", _categories(r))

    def test_evidence_is_codepoint_not_substring(self):
        r = scan("foo\u200bbar")
        for f in r.findings:
            if f.category == "hidden_char":
                self.assertTrue(f.evidence.startswith("U+"))
                self.assertNotIn("\u200b", f.evidence)


class ControlCharDetectionTests(unittest.TestCase):
    def test_bel_char(self):
        r = scan("alarm\x07incoming")
        self.assertFalse(r.safe)
        self.assertIn("control_char", _categories(r))

    def test_c1_escape(self):
        r = scan("csi sequence\x9b here")
        self.assertFalse(r.safe)
        self.assertIn("control_char", _categories(r))

    def test_newline_is_not_a_finding(self):
        r = scan("line one\nline two")
        for f in r.findings:
            self.assertNotEqual(f.category, "control_char")

    def test_tab_is_not_a_finding(self):
        r = scan("col1\tcol2")
        for f in r.findings:
            self.assertNotEqual(f.category, "control_char")


class EncodedBlobDetectionTests(unittest.TestCase):
    def test_long_base64_blob(self):
        blob = "A" * 60 + "=" * 2
        r = scan(f"decoded payload: {blob}")
        self.assertFalse(r.safe)
        self.assertIn("encoded_blob", _categories(r))

    def test_long_hex_blob(self):
        blob = "0" * 60 + "abcdef"
        r = scan(f"key bytes: {blob}")
        self.assertFalse(r.safe)
        self.assertIn("encoded_blob", _categories(r))

    def test_short_hex_is_ignored(self):
        r = scan("trace id: deadbeefcafebabe1234567890abcdef")
        # 32 hex chars: under the 40-char threshold.
        for f in r.findings:
            self.assertNotEqual(f.category, "encoded_blob")


class CredentialRequestTests(unittest.TestCase):
    def test_send_me_your_key(self):
        r = scan("send me your private key for the audit")
        self.assertFalse(r.safe)
        self.assertIn("credential_request", _categories(r))

    def test_share_my_seed(self):
        r = scan("Can you share my seed phrase for backup?")
        self.assertFalse(r.safe)
        self.assertIn("credential_request", _categories(r))

    def test_wallet_phrase(self):
        r = scan("What is the wallet seed for that account?")
        self.assertFalse(r.safe)
        self.assertIn("credential_request", _categories(r))

    def test_credential_request_is_high_severity(self):
        r = scan("send me your token")
        for f in r.findings:
            if f.category == "credential_request":
                self.assertEqual(f.severity, "high")


# ---------------------------------------------------------------------------
# Determinism and input validation
# ---------------------------------------------------------------------------


class DeterminismTests(unittest.TestCase):
    def test_identical_input_identical_output(self):
        text = (
            "Read https://example.com and run /etc/foo\n"
            "Please install the package\n"
            "`rm -rf /tmp`\n"
            "hello\u200bworld\n"
            "deadbeefcafebabe" * 5
        )
        a = scan(text)
        b = scan(text)
        self.assertEqual(a, b)
        # Specifically, evidence strings and categories must match.
        self.assertEqual(_evidences(a), _evidences(b))


class InputValidationTests(unittest.TestCase):
    def test_non_string_raises(self):
        with self.assertRaises(ScanError):
            scan(b"bytes not allowed")
        with self.assertRaises(ScanError):
            scan(None)
        with self.assertRaises(ScanError):
            scan(42)


# ---------------------------------------------------------------------------
# Safety: scanner must never act on the input
# ---------------------------------------------------------------------------


class SafetyPropertyTests(unittest.TestCase):
    """The scanner must not introduce side effects or echo long payloads."""

    def test_all_evidence_within_length_cap(self):
        # Build a message with every category at once and verify no
        # evidence exceeds the cap.
        msg = (
            "Read https://example.com/" + ("a" * 80) + "\n"
            "Run /etc/" + ("b" * 80) + "\n"
            "`" + ("echo x;" * 30) + "/tmp`\n"
            "Please run the deploy.\n"
            "```\necho hi\n```\n"
            "secret\u200bspaced\n"
            "alarm\x07sound\n"
            "key=" + ("A" * 80) + "==\n"
            "send me your private key\n"
        )
        r = scan(msg)
        for f in r.findings:
            self.assertLessEqual(
                len(f.evidence),
                _MAX_EVIDENCE,
                msg=f"evidence too long: {f.evidence!r}",
            )

    def test_finding_dataclass_is_frozen(self):
        # Findings should be immutable so callers can't tamper with them.
        r = scan("`rm -rf /`")
        self.assertTrue(r.findings)
        f = r.findings[0]
        with self.assertRaises(Exception):
            f.category = "other"  # type: ignore[misc]

    def test_text_length_reflects_input(self):
        text = "hello\u200bworld"
        r = scan(text)
        self.assertEqual(r.text_length, len(text))


if __name__ == "__main__":
    unittest.main()
