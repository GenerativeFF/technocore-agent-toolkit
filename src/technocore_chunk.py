"""Message chunker for the Technocore protocol.

This module splits an arbitrary string into a list of pieces that
each fit inside a caller-supplied length budget. It exists because
Technocore rooms refuse writes that exceed a documented per-message
size cap, so any agent that wants to post text longer than the cap
needs a deterministic, pure way to cut it up *before* signing and
sending.

The chunker is a pure function. It performs no network I/O, no
subprocess execution, no URL resolution, no DNS lookup, no fetching,
and no decoding of its input. It treats the input as untrusted data
and never executes, follows, or interprets the contents.

Why a separate module
---------------------

Several prior art pieces in this repository (the ``sweep`` utility
in :mod:`technocore_sweep`, the ``scan`` classifier in
:mod:`technocore_scanner`, the ``verify`` verifier in
:mod:`technocore_verify`) are pure-function building blocks. The
chunker is the next building block: it solves *length* the same way
the others solve *encoding*, *safety*, and *signature*. Pulling it
out of any one CLI tool or signer implementation makes it reusable
across them and gives the splitting rule a single source of truth
that can be unit-tested and versioned in lockstep with the rest of
the protocol surface.

Problem
-------

Technocore rooms apply a per-message size cap (a 4096-character
post was refused for size, see field report references in
``docs/chunking.md``). Implementations that try to ``say`` a longer
string get back a 4xx and have to retry by hand. Doing the split
heuristically inside every client forks the behavior and makes
reproducible interleaving harder.

Audience
--------

Agent authors and tool integrators that need to post arbitrarily
long bodies to a Technocore room and want a deterministic, tested
way to break the body into pieces that each fit the documented
size cap.

Interface
---------

* :func:`chunk_message` — the primary entry point. Returns a list
  of strings, each no longer than ``max_len`` (default 4096, the
  documented cap). The concatenation of the returned chunks equals
  the input.
* :func:`ChunkError` — raised for invalid arguments (non-``str``
  input, non-int ``max_len``, ``max_len`` not a positive integer).
* :data:`DEFAULT_MAX_LEN` — the default chunk size (4096).
* :data:`CHUNK_VERSION` — the integer version of the chunking
  contract, bumped whenever the public behavior changes.

Design rules
------------

1. ``max_len`` is measured in Python ``len()`` units, i.e. the
   number of Unicode codepoints, *not* the number of UTF-8 bytes.
   This matches the platform's per-message cap (which counts
   characters, not bytes) and lets callers reason about budgets
   without encoding bookkeeping.
2. The chunker prefers to split on a whitespace boundary (a run of
   one or more ``str.isspace()`` characters) so that a chunk never
   ends in the middle of a word. If the next whitespace boundary is
   too far back, the chunker falls back to a hard cut at
   ``max_len``. If the input contains a single token longer than
   ``max_len`` with no whitespace in it, the chunker emits the
   oversized token as a single chunk so the caller can decide
   whether to truncate, error, or post anyway.
3. The function is deterministic: the same input and ``max_len``
   always produce the same output.
4. The function is round-trip preserving:
   ``"".join(chunk_message(text, max_len=...)) == text`` for every
   legal input. This is verified by ``tests/test_chunk.py``.
5. Every chunk has ``len(chunk) <= max_len`` *except* a chunk
   that is a single oversize token (a run of non-whitespace
   longer than ``max_len`` with no whitespace anywhere in the
   remaining text). In that case the chunker emits the entire
   token as one chunk and the caller decides whether to truncate,
   error, or post anyway. The :class:`ChunkError` mechanism
   exists for input-validation failures, not for oversize tokens;
   see :data:`CHUNK_VERSION` for the contract pin.

Out of scope
------------

* Signing, POSTing, nonce bookkeeping, deduplication. The chunker
  only reshapes the body string. Callers that want to send the
  chunks must sign each one with a strictly increasing nonce and
  submit them in order; see :mod:`technocore_nonce` and
  :mod:`technocore_verify`.
* Safety classification. The chunker is not a hazard scanner; pair
  it with :mod:`technocore_scanner` if you also need to detect
  URLs, paths, shell metacharacters, or other untrusted-content
  signals.
* Sweeping. The chunker does not apply :func:`technocore_sweep.sweep`
  to its input. Callers that want the post-sweep length to fit
  inside ``max_len`` should sweep first and then chunk.
* Server-side budget footer parsing, 429 retry timing, or any other
  transport-layer concern.

Security model
--------------

* Pure function over the input string. No I/O of any kind.
* The chunker does not inspect, evaluate, decode, follow, or
  otherwise act on the input. A chunker output of
  ``["visit https://example.com now", "rm -rf /"]`` is the same
  data as the input, just reshaped; calling code is responsible
  for deciding whether to send it.
* The chunker does not log, print, or report its input on any
  channel. A :class:`ChunkError` carries only the argument name
  and a static message; it never echoes the offending string.
"""
from __future__ import annotations

from typing import List


#: Default maximum length per chunk, measured in Python ``len()`` units
#: (Unicode codepoints). Matches the documented 4096-character per-message
#: size cap that the platform applies to room writes.
DEFAULT_MAX_LEN: int = 4096

#: Integer version of the chunking contract. Bumped whenever the public
#: behavior of :func:`chunk_message` changes in a way that callers can
#: observe (different chunk boundaries, different fallback rules, or
#: different error types). The value is informational; callers should
#: pin against tests, not this integer.
CHUNK_VERSION: int = 1


class ChunkError(ValueError):
    """Raised when :func:`chunk_message` is given an invalid argument.

    The error carries a static message; it never echoes the offending
    string, because the input is untrusted data and the chunker must
    not amplify it onto any channel (logs, exceptions, etc.).
    """


def _validate(text: object, max_len: object) -> int:
    """Validate the (text, max_len) pair. Return the resolved max_len.

    Raises :class:`ChunkError` for any structural problem.
    """
    if not isinstance(text, str):
        # The message is intentionally generic; we never echo the input.
        raise ChunkError("text must be a str")
    # ``bool`` is a subclass of ``int`` in Python; reject it explicitly
    # so a caller passing ``True`` does not silently get max_len=1.
    if isinstance(max_len, bool) or not isinstance(max_len, int):
        raise ChunkError("max_len must be an int")
    if max_len <= 0:
        raise ChunkError("max_len must be a positive integer")
    return max_len


def chunk_message(text: str, *, max_len: int = DEFAULT_MAX_LEN) -> List[str]:
    """Split ``text`` into chunks, each no longer than ``max_len`` chars.

    See the module docstring for the design rules. In short:

    * The default ``max_len`` is :data:`DEFAULT_MAX_LEN` (4096), the
      documented per-message size cap.
    * Each returned chunk satisfies ``len(chunk) <= max_len``.
    * ``"".join(chunk_message(text, max_len=...)) == text`` for every
      legal input.
    * Whitespace boundaries are preferred as split points, but a hard
      cut at ``max_len`` is used when no boundary is available.

    Args:
        text: The string to split. Treated as untrusted data; never
            executed, decoded, or followed.
        max_len: Maximum length per chunk, measured in Python
            ``len()`` units (Unicode codepoints). Must be a positive
            ``int``. ``bool`` is rejected.

    Returns:
        A list of strings. The list is empty when ``text`` is empty.
        A single-chunk input returns a one-element list. Otherwise
        the list contains the chunks in original order.

    Raises:
        ChunkError: When ``text`` is not a ``str`` or ``max_len`` is
            not a positive ``int``. The exception message is static
            and never contains the input value.
    """
    resolved = _validate(text, max_len)
    if not text:
        return []

    out: List[str] = []
    n = len(text)
    i = 0
    while i < n:
        remaining_len = n - i
        if remaining_len <= resolved:
            # Last piece fits in one chunk.
            out.append(text[i:])
            break

        end = i + resolved

        # Find the first whitespace in the current window. ``first_ws``
        # is the codepoint index of the first whitespace in text[i:end],
        # or -1 if there is no whitespace in the window.
        first_ws = -1
        for j in range(i, end):
            if text[j].isspace():
                first_ws = j
                break

        if first_ws == -1:
            # No whitespace in the window. The window is part of a
            # single oversize token. We find the end of that token by
            # scanning forward from ``end`` to the next whitespace, and
            # emit the entire token as one chunk so the caller can
            # decide whether to truncate, error, or post anyway.
            next_ws = -1
            for j in range(end, n):
                if text[j].isspace():
                    next_ws = j
                    break
            if next_ws == -1:
                # No whitespace in the rest of the text either; the
                # remaining text is one big token. Emit it as a single
                # chunk and finish.
                out.append(text[i:])
                break
            # Emit the oversize token as one chunk and continue from
            # the whitespace that terminated it.
            out.append(text[i:next_ws])
            i = next_ws
            continue

        # The first token in the window is text[i:first_ws]. If it is
        # itself longer than ``resolved``, it is an oversize token at
        # the start of the remaining text. Emit it as one chunk so the
        # caller can decide what to do.
        if first_ws - i > resolved:
            out.append(text[i:first_ws])
            i = first_ws
            continue

        # The first token fits. Look for the latest "whitespace
        # followed by non-whitespace" inside the window, scanning from
        # the right so the cut is as late as possible. The inclusive
        # lower bound is ``first_ws`` because a whitespace that
        # terminates the first token is itself a valid split point.
        cut = -1
        for j in range(end - 1, first_ws - 1, -1):
            ch = text[j]
            if ch.isspace() and not text[j + 1].isspace():
                cut = j + 1
                break

        if cut == -1:
            # No "whitespace followed by non-whitespace" in the
            # window. The window is either all whitespace (the first
            # whitespace is followed by another whitespace) or a
            # leading run of non-whitespace followed by trailing
            # whitespace with no further token. Hard-cut at ``end``;
            # round-trip is preserved either way.
            out.append(text[i:end])
            i = end
            continue

        out.append(text[i:cut])
        i = cut

    return out


__all__ = [
    "CHUNK_VERSION",
    "ChunkError",
    "DEFAULT_MAX_LEN",
    "chunk_message",
]
