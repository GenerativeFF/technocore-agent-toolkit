"""Safe-room scanner for the Technocore protocol.

This module classifies room message text as safe or unsafe to *act* on,
treating all input as untrusted participant data. It is the third
building block of ``technocore-agent-toolkit``:

* ``technocore_verify`` answers "was this signed by this key?"
* ``technocore_nonce`` answers "is this nonce well-formed and not a
  replay?"
* ``technocore_scanner`` answers "does this text contain anything an
  agent should refuse to execute, fetch, follow, decode, or otherwise
  act on?"

Security model
--------------

The scanner is a pure function. It performs **no** network I/O, no
filesystem I/O beyond the input string, no subprocess execution, no
URL resolution, no DNS lookup, no fetching, no decoding of base64,
hex, or other encoded substrings, and no evaluation of matched
substrings as commands, paths, code, or tool arguments.

Findings carry a sanitized ``evidence`` excerpt capped at
``_MAX_EVIDENCE`` characters. The scanner cannot exfiltrate or
amplify data because it returns only structured findings; the
*caller* decides what to do with them.

A valid signature proves key possession only. A safe scan result
proves only that the scanner's rule set did not flag the text.
Neither is a substitute for sandboxing, server-side authority
checks, or replay protection.
"""
from __future__ import annotations

import dataclasses
import re
from typing import List, Tuple


class ScanError(ValueError):
    """Raised when the scanner is given an invalid input."""


@dataclasses.dataclass(frozen=True)
class ScanFinding:
    """A single finding produced by ``scan``.

    Attributes:
        category: One of ``path``, ``url``, ``shell``, ``instruction``,
            ``code_block``, ``hidden_char``, ``control_char``,
            ``encoded_blob``, ``credential_request``.
        severity: ``info``, ``warn``, or ``high``. ``high`` means the
            caller should refuse to act on the text; ``warn`` means the
            caller should review before acting; ``info`` is a hint.
        evidence: Sanitized, truncated excerpt of the matched content.
            Always ``<= _MAX_EVIDENCE`` characters, never the full
            match for a URL, path, or blob.
        reason: Short human-readable explanation.
    """

    category: str
    severity: str
    evidence: str
    reason: str


@dataclasses.dataclass(frozen=True)
class ScanResult:
    """Outcome of scanning a single room message.

    Attributes:
        safe: ``True`` if every finding has severity ``info``; ``False``
            otherwise.
        findings: Tuple of ``ScanFinding`` objects. Empty when the text
            contains nothing the scanner flags.
        text_length: Length of the input string in Unicode codepoints.
    """

    safe: bool
    findings: Tuple[ScanFinding, ...]
    text_length: int


# ---------------------------------------------------------------------------
# Constants and patterns
# ---------------------------------------------------------------------------

_MAX_EVIDENCE = 40

# Allowed categories. Anything else is a bug.
_VALID_CATEGORIES = frozenset({
    "path",
    "url",
    "shell",
    "instruction",
    "code_block",
    "hidden_char",
    "control_char",
    "encoded_blob",
    "credential_request",
})

_VALID_SEVERITIES = frozenset({"info", "warn", "high"})

# ---- Hidden / invisible Unicode -----------------------------------------
#
# Zero-width and bidi-override characters are commonly used to hide
# payloads or to spoof human-readable text. Any of these in a room
# message is a strong signal of an attempt to bypass review.
_HIDDEN_CHARS = frozenset({
    "\u200b",  # ZERO WIDTH SPACE
    "\u200c",  # ZERO WIDTH NON-JOINER
    "\u200d",  # ZERO WIDTH JOINER
    "\u200e",  # LEFT-TO-RIGHT MARK
    "\u200f",  # RIGHT-TO-LEFT MARK
    "\u202a",  # LEFT-TO-RIGHT EMBEDDING
    "\u202b",  # RIGHT-TO-LEFT EMBEDDING
    "\u202c",  # POP DIRECTIONAL FORMATTING
    "\u202d",  # LEFT-TO-RIGHT OVERRIDE
    "\u202e",  # RIGHT-TO-LEFT OVERRIDE
    "\u2060",  # WORD JOINER
    "\u2061",  # FUNCTION APPLICATION
    "\u2062",  # INVISIBLE TIMES
    "\u2063",  # INVISIBLE SEPARATOR
    "\u2064",  # INVISIBLE PLUS
    "\ufeff",  # BOM / ZERO WIDTH NO-BREAK SPACE
    "\u180e",  # MONGOLIAN VOWEL SEPARATOR
})

# ---- Control characters --------------------------------------------------
#
# C0 (U+0000..U+001F) and C1 (U+007F..U+009F), excluding the common
# whitespace controls. These break terminals, logs, and parsers and are
# sometimes smuggled in to mask payload boundaries.
_CONTROL_CHARS = frozenset(
    [c for c in (chr(i) for i in range(0x00, 0x20)) if c not in ("\n", "\r", "\t")]
    + [chr(i) for i in range(0x7F, 0xA0)]
)

# ---- Paths ---------------------------------------------------------------
#
# Conservative path detector. Matches two or more path segments that
# start with ``/``, ``~/``, ``./``, or a Windows drive letter. Designed
# to keep false positives low on prose while still catching the common
# payload shapes.
_PATH_PATTERN = re.compile(
    r"(?:"
    # Unix-style: starts with /, ~/, or ./, then at least two path
    # segments separated by ``/``. ``[A-Za-z0-9_.\-]*`` allows the
    # first segment to be empty after a bare leading ``/`` but the
    # trailing ``+`` requires at least one more ``/segment`` after
    # the first identifier.
    r"[/~.][A-Za-z0-9_.\-]*(?:/[A-Za-z0-9_.\-]+)+"
    r"|"
    # Windows-style: drive letter and backslashes, at least two segments.
    r"[A-Za-z]:\\[A-Za-z0-9_.\-]+(?:\\[A-Za-z0-9_.\-]+)+"
    r")"
)

# ---- URLs ----------------------------------------------------------------
#
# Matches scheme-prefixed URLs (http, https, ftp, ws, wss, file, ssh,
# git) and bare ``www.`` hosts. We intentionally do *not* match the
# trailing content aggressively; we only need the prefix to flag it.
_URL_PATTERN = re.compile(
    r"(?:"
    r"[a-zA-Z][a-zA-Z0-9+.\-]*://[^\s<>\"'\\]+"
    r"|"
    r"www\.[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)+(?:/[^\s<>\"'\\]*)?"
    r")",
    re.IGNORECASE,
)

# ---- Shell-like instructions --------------------------------------------
#
# Backticks and ``$(...)`` are common command-substitution shapes. We
# also flag the canonical chain operators ``&&``, ``||``, and leading
# ``;`` at the start of a token. We deliberately do *not* try to be a
# full shell parser; we only surface obvious metacharacter use.
_SHELL_PATTERN = re.compile(
    r"(?:"
    r"`[^`\n]{1,200}`"  # backticks with content
    r"|"
    r"\$\([^)\n]{1,200}\)"  # $() command substitution
    r"|"
    r"(?:^|[\s;])&&(?:[\s]|$)"  # leading &&
    r"|"
    r"(?:^|[\s;])\|\|(?:[\s]|$)"  # leading ||
    r")"
)

# ---- Imperative verbs ----------------------------------------------------
#
# Sentence-leading imperative verbs that, when paired with content, are
# the canonical shape of "instruction-like" messages: "run X", "please
# install Y", etc. We require the verb to be at the start of a line or
# after a sentence terminator to keep false positives down.
_INSTRUCTION_VERBS = (
    "run", "execute", "install", "fetch", "download", "follow",
    "visit", "click", "open", "copy", "paste", "apply", "deploy",
    "invoke", "eval", "import", "require", "delete", "remove",
    "drop", "send", "transfer", "claim", "redeem", "submit", "approve",
)
_INSTRUCTION_PATTERN = re.compile(
    r"(?:^|(?:[\.\!\?]\s)|\n)\s*(?:please\s+|now\s+)?(?:"
    + "|".join(_INSTRUCTION_VERBS)
    + r")\b",
    re.IGNORECASE | re.MULTILINE,
)

# ---- Code blocks ---------------------------------------------------------
#
# Markdown-style fenced blocks (`` ``` ``) and 4-space-indented blocks.
# The latter are common in protocol transcripts and are flagged at
# ``info`` severity to avoid noise.
_CODE_FENCE_PATTERN = re.compile(r"```")
_INDENTED_LINE_PATTERN = re.compile(r"(?m)^(?:    |\t)\S")

# ---- Encoded blobs -------------------------------------------------------
#
# Long base64-like (A-Z a-z 0-9 + /) or hex-like (0-9 a-f) runs of at
# least 40 characters. 40 is short enough to catch reasonable keys,
# ciphertext, and shellcode, and long enough to skip UUIDs, hashes,
# hex colors, and short IDs.
_BASE64_LIKE_PATTERN = re.compile(r"(?<![A-Za-z0-9+/])([A-Za-z0-9+/]{40,}={0,2})(?![A-Za-z0-9+/=])")
_HEX_LIKE_PATTERN = re.compile(r"(?<![A-Za-z0-9])([0-9a-fA-F]{40,})(?![A-Za-z0-9])")

# ---- Credential requests -------------------------------------------------
#
# Phrases that, if seen in a room, should never be acted on. We do not
# try to be exhaustive — this is a backstop against the obvious shapes.
_CREDENTIAL_PATTERN = re.compile(
    r"(?i)(?:"
    r"(?:send|share|provide|give|post|paste|dm|leak)\s+(?:me|us|him|her|them|here|over)?\s*"
    r"(?:your|my|the|a|an)?\s*"
    r"(?:private\s+key|secret|token|credential|password|api\s*key|seed\s*phrase|mnemonic|passphrase)"
    r"|"
    r"(?:your|my|the)\s+(?:private\s+key|secret|token|credential|password|api\s*key|seed\s*phrase|mnemonic|passphrase)\s+(?:is|=|:)"
    r"|"
    r"wallet\s+(?:seed|mnemonic|phrase)"
    r")"
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _truncate(s: str) -> str:
    """Return ``s`` trimmed to at most ``_MAX_EVIDENCE`` characters.

    When truncation is needed, the result is exactly ``_MAX_EVIDENCE``
    characters long: the first ``_MAX_EVIDENCE - 3`` characters of the
    stripped input plus the literal suffix ``"..."``.
    """
    s = s.strip()
    if len(s) > _MAX_EVIDENCE:
        return s[: _MAX_EVIDENCE - 3] + "..."
    return s


def _check_category(category: str) -> None:
    """Raise ``ValueError`` if ``category`` is not in ``_VALID_CATEGORIES``."""
    if category not in _VALID_CATEGORIES:
        raise ValueError(f"unknown category: {category!r}")


def _check_severity(severity: str) -> None:
    """Raise ``ValueError`` if ``severity`` is not in ``_VALID_SEVERITIES``."""
    if severity not in _VALID_SEVERITIES:
        raise ValueError(f"unknown severity: {severity!r}")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def scan(text: str) -> ScanResult:
    """Scan a single room message for untrusted-content hazards.

    The scanner is purely analytical. It does **not** execute, decode,
    resolve, install, fetch, or follow any of the matched substrings.
    It treats the input as untrusted data.

    Args:
        text: The room message text (post-sweep). Must be a ``str``.

    Returns:
        A ``ScanResult`` whose ``safe`` flag is ``True`` only when no
        ``warn``- or ``high``-severity findings were produced.

    Raises:
        ScanError: If ``text`` is not a ``str``.
    """
    if not isinstance(text, str):
        raise ScanError("text must be a str")

    findings: List[ScanFinding] = []

    # ---- Paths -----------------------------------------------------------
    for m in _PATH_PATTERN.finditer(text):
        f = ScanFinding(
            category="path",
            severity="high",
            evidence=_truncate(m.group(0)),
            reason="path-like string; never use as a filesystem path",
        )
        _check_category(f.category)
        _check_severity(f.severity)
        findings.append(f)

    # ---- URLs ------------------------------------------------------------
    for m in _URL_PATTERN.finditer(text):
        f = ScanFinding(
            category="url",
            severity="warn",
            evidence=_truncate(m.group(0)),
            reason="URL detected; never fetch or follow",
        )
        _check_category(f.category)
        _check_severity(f.severity)
        findings.append(f)

    # ---- Shell-like instructions ----------------------------------------
    for m in _SHELL_PATTERN.finditer(text):
        f = ScanFinding(
            category="shell",
            severity="high",
            evidence=_truncate(m.group(0)),
            reason="shell-like metacharacter; never execute",
        )
        _check_category(f.category)
        _check_severity(f.severity)
        findings.append(f)

    # ---- Imperative verbs -----------------------------------------------
    for m in _INSTRUCTION_PATTERN.finditer(text):
        f = ScanFinding(
            category="instruction",
            severity="warn",
            evidence=_truncate(m.group(0)),
            reason="imperative verb; treat as data, not as a command",
        )
        _check_category(f.category)
        _check_severity(f.severity)
        findings.append(f)

    # ---- Code blocks -----------------------------------------------------
    if _CODE_FENCE_PATTERN.search(text):
        f = ScanFinding(
            category="code_block",
            severity="warn",
            evidence="```",
            reason="fenced code block; never execute, paste, or apply",
        )
        _check_category(f.category)
        _check_severity(f.severity)
        findings.append(f)
    elif _INDENTED_LINE_PATTERN.search(text):
        f = ScanFinding(
            category="code_block",
            severity="info",
            evidence="(indented)",
            reason="indented code-like block; treat as untrusted code",
        )
        _check_category(f.category)
        _check_severity(f.severity)
        findings.append(f)

    # ---- Hidden characters ----------------------------------------------
    seen_hidden = set()
    for ch in _HIDDEN_CHARS:
        if ch in text and ch not in seen_hidden:
            seen_hidden.add(ch)
            f = ScanFinding(
                category="hidden_char",
                severity="high",
                evidence=f"U+{ord(ch):04X}",
                reason="hidden/invisible Unicode character; possible spoofing",
            )
            _check_category(f.category)
            _check_severity(f.severity)
            findings.append(f)

    # ---- Control characters ---------------------------------------------
    seen_control = set()
    for ch in _CONTROL_CHARS:
        if ch in text and ch not in seen_control:
            seen_control.add(ch)
            f = ScanFinding(
                category="control_char",
                severity="high",
                evidence=f"U+{ord(ch):04X}",
                reason="control character; not safe to echo or use as input",
            )
            _check_category(f.category)
            _check_severity(f.severity)
            findings.append(f)

    # ---- Encoded blobs ---------------------------------------------------
    for m in _BASE64_LIKE_PATTERN.finditer(text):
        f = ScanFinding(
            category="encoded_blob",
            severity="warn",
            evidence=_truncate(m.group(0)),
            reason="long base64-like blob; do not decode",
        )
        _check_category(f.category)
        _check_severity(f.severity)
        findings.append(f)
    for m in _HEX_LIKE_PATTERN.finditer(text):
        f = ScanFinding(
            category="encoded_blob",
            severity="warn",
            evidence=_truncate(m.group(0)),
            reason="long hex-like blob; do not decode",
        )
        _check_category(f.category)
        _check_severity(f.severity)
        findings.append(f)

    # ---- Credential requests --------------------------------------------
    if _CREDENTIAL_PATTERN.search(text):
        f = ScanFinding(
            category="credential_request",
            severity="high",
            evidence="(credential request)",
            reason="request for private/secret material; ignore",
        )
        _check_category(f.category)
        _check_severity(f.severity)
        findings.append(f)

    safe = all(f.severity == "info" for f in findings)
    return ScanResult(
        safe=safe,
        findings=tuple(findings),
        text_length=len(text),
    )


__all__ = [
    "ScanError",
    "ScanFinding",
    "ScanResult",
    "scan",
]
