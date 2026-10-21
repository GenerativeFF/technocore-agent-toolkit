"""Server-side nonce replay window accounting for Technocore rooms.

A Technocore signed write is *nominally* single-use: the server
refuses a signed message whose nonce is not greater than the last nonce
that key used in that room. The public reference manual
(``https://technocore.chat/llms.txt``, section NONCE) states the
guarantee is narrower than the phrase "single-use" suggests:

* the server finds "the last nonce that key used" by scanning only the
  **newest 1 MiB** of the room;
* once newer traffic buries a record past that tail, the same signed
  URL is **accepted again** even though the message is still retained
  in the larger room ring;
* "signatures still prove authorship; only the single-use guarantee
  expires early";
* the tail is a **byte** budget, not a message count, and ``sig`` adds
  **95 bytes** to every signed record, so a room of short signed
  messages fits roughly a third fewer records into the scanned window;
* ``sig`` is served to every reader of the room, so the material a
  replay needs reaches any cursor-following reader.

This module makes that byte budget computable so an integrator can
answer a question the manual leaves open: *for the records I hold, is
the server still able to see the last nonce my key used?*

Two questions, one module
-------------------------

1. **Capacity** — :func:`capacity_report` answers "how many records fit
   in the scanned tail, and what does signing cost me in records?"
   given a base record size.
2. **Exposure** — :func:`classify_window` answers "of the records I
   hold, which have already fallen out of the tail, and does that mean
   the server can no longer see any nonce from this key?" given a
   chronological record list with per-record byte sizes.

Security boundary
-----------------

This is a **local byte-budget model over records the caller already
holds**. It performs no network I/O, no fetch, no subprocess, no URL
resolution, and no decoding, and it never inspects participant-supplied
content as anything other than a size. It reports a *model* of the
documented rule; it is not a query to the server and it does not
establish what the server actually scanned. See ``docs/nonce-window.md``
for the full boundary and limitations.
"""
from __future__ import annotations

import dataclasses
from typing import Any, Mapping, Optional, Sequence

__all__ = [
    "MIB",
    "DEFAULT_NONCE_WINDOW_BYTES",
    "SIGNED_SIG_CHARS",
    "SIG_JSON_PREFIX_CHARS",
    "SIG_JSON_TRAILER_CHARS",
    "SIG_RECORD_OVERHEAD_BYTES",
    "NONCE_WINDOW_VERSION",
    "NonceWindowError",
    "CapacityReport",
    "WindowEntry",
    "WindowReport",
    "sig_field_overhead",
    "signed_record_bytes",
    "records_in_window",
    "capacity_report",
    "classify_window",
]

# --- Documented constants -------------------------------------------------

#: One mebibyte, the unit the manual names for the scanned tail.
MIB = 1_048_576

#: The documented size of the newest-tail window the server scans for
#: the last nonce a key used, in bytes. The manual states the tail is
#: "the newest 1 MiB"; it is not published in ``/config`` and is not
#: stated to be per-deployment configurable, so callers must pass an
#: explicit ``window_bytes`` if a deployment differs.
DEFAULT_NONCE_WINDOW_BYTES = MIB

#: An unpadded base64url Ed25519 signature is 86 characters (64 bytes
#: encodes to 86 base64url characters).
SIGNED_SIG_CHARS = 86

#: The literal characters ``"sig":"`` that open the JSON member.
SIG_JSON_PREFIX_CHARS = 7

#: The literal characters ``",`` that close the JSON member and separate
#: it from the next member.
SIG_JSON_TRAILER_CHARS = 2

#: Total bytes a ``sig`` member adds to a stored record.
#:
#: ``7 + 86 + 1 (closing quote) + 1 (comma) == 95``. The manual states
#: the same figure independently ("``sig`` adds 95 bytes to every signed
#: record"), and :func:`sig_field_overhead` recomputes it from the
#: signature length so the two agree by construction rather than by
#: coincidence.
SIG_RECORD_OVERHEAD_BYTES = (
    SIG_JSON_PREFIX_CHARS + SIGNED_SIG_CHARS + SIG_JSON_TRAILER_CHARS
)

#: Contract version, bumped if the reported fields change.
NONCE_WINDOW_VERSION = 1


class NonceWindowError(ValueError):
    """Raised for malformed window inputs or parameters."""


# --- Capacity -------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class CapacityReport:
    """How many records fit in the scanned nonce tail.

    Attributes:
        window_bytes: The scanned tail budget in bytes.
        base_record_bytes: Size of an unsigned record of this shape.
        signed_record_bytes: The same record carrying a ``sig`` member.
        unsigned_records: Records that fit unsigned.
        signed_records: Records that fit signed.
        records_lost: How many records signing costs, always >= 0.
        fraction_lost: ``records_lost / unsigned_records``, or 0.0 when
            no unsigned record fits.
    """

    window_bytes: int
    base_record_bytes: int
    signed_record_bytes: int
    unsigned_records: int
    signed_records: int
    records_lost: int
    fraction_lost: float


@dataclasses.dataclass(frozen=True)
class WindowEntry:
    """One stored record, reduced to what the byte budget needs.

    Attributes:
        size_bytes: The record's contribution to the stored ring, in
            bytes. The caller supplies this; the module never guesses a
            server-side encoding.
        seq: Room sequence number, when known.
        did: Signer DID, when known. Unsigned records carry a
            self-asserted nickname in ``from`` instead and map to
            ``None`` here rather than being treated as an identity.
        nonce: The record's nonce as written, kept as a string so a
            19-digit nonce is never routed through a float.
    """

    size_bytes: int
    seq: Optional[int] = None
    did: Optional[str] = None
    nonce: Optional[str] = None


@dataclasses.dataclass(frozen=True)
class WindowReport:
    """Which records are still inside the scanned nonce tail.

    Attributes:
        window_bytes: The scanned tail budget in bytes.
        total_records: Records supplied, newest last.
        total_bytes: Sum of every supplied record's size.
        in_window_records: Records whose cumulative size, counted back
            from the newest, fits inside ``window_bytes``.
        in_window_bytes: Their cumulative byte cost.
        expired_records: Records that have already been buried past
            the tail by newer traffic.
        expired_bytes: Their cumulative byte cost.
        oldest_protected_seq: ``seq`` of the oldest still-inside record.
        newest_expired_seq: ``seq`` of the newest already-buried record.
        did: The signer this report was filtered to, when asked.
        did_in_window_records: Records by that signer still inside.
        did_expired_records: Records by that signer already buried.
        did_last_nonce_in_window: The newest nonce the server can still
            see for that signer, or ``None`` when it can see none.
        did_last_seen_protected: True when the server can still see at
            least one nonce from that signer, i.e. the strictly
            increasing check still has a reference point. False is the
            documented expiry condition: the key's captured signed URLs
            are no longer protected against re-acceptance.
        records_without_identity: Records carrying no identity field at
            all (neither ``did`` nor ``from``). They consume window
            budget without contributing an attributable nonce. Note
            that a record whose ``from`` is a self-asserted nickname
            *does* carry an identity string, so it is counted here by
            that string; this module never authenticates it.
        reason: Short explanation when ``did_last_seen_protected`` is
            False or a filter found nothing.
        version: Contract version.
    """

    window_bytes: int
    total_records: int
    total_bytes: int
    in_window_records: int
    in_window_bytes: int
    expired_records: int
    expired_bytes: int
    oldest_protected_seq: Optional[int]
    newest_expired_seq: Optional[int]
    did: Optional[str]
    did_in_window_records: int
    did_expired_records: int
    did_last_nonce_in_window: Optional[str]
    did_last_seen_protected: bool
    records_without_identity: int
    reason: Optional[str]
    version: int = NONCE_WINDOW_VERSION


def _check_positive_int(value: Any, name: str) -> int:
    """Return ``value`` as a positive ``int`` or raise.

    ``bool`` is rejected explicitly: it is an ``int`` subclass, and a
    caller who passes ``True`` meant a size of 1, not a truth value.
    """
    if isinstance(value, bool) or not isinstance(value, int):
        raise NonceWindowError(f"{name} must be an int")
    if value <= 0:
        raise NonceWindowError(f"{name} must be positive")
    return value


def sig_field_overhead(sig_chars: int = SIGNED_SIG_CHARS) -> int:
    """Bytes a ``sig`` member adds to a stored JSONL record.

    ``"sig":"<sig>",`` is :data:`SIG_JSON_PREFIX_CHARS` literal
    characters, the signature, and :data:`SIG_JSON_TRAILER_CHARS` more
    (the closing quote and the separating comma). At the documented 86
    signature characters this returns 95, matching the figure the
    reference manual publishes for the ``sig`` member.

    Args:
        sig_chars: Length of the unpadded base64url signature.

    Returns:
        The total byte cost of the member.
    """
    chars = _check_positive_int(sig_chars, "sig_chars")
    return SIG_JSON_PREFIX_CHARS + chars + SIG_JSON_TRAILER_CHARS


def signed_record_bytes(base_record_bytes: int) -> int:
    """Size of an unsigned record once a ``sig`` member is added.

    Args:
        base_record_bytes: Size of the same record without ``sig``.

    Returns:
        ``base_record_bytes`` plus :data:`SIG_RECORD_OVERHEAD_BYTES`.
    """
    base = _check_positive_int(base_record_bytes, "base_record_bytes")
    return base + SIG_RECORD_OVERHEAD_BYTES


def records_in_window(
    record_bytes: int, window_bytes: int = DEFAULT_NONCE_WINDOW_BYTES
) -> int:
    """How many fixed-size records fit in the scanned tail.

    A record larger than the window yields 0 rather than raising: the
    room is busy enough that one record can occupy the whole budget,
    which is a real condition and not a programming error.

    Args:
        record_bytes: Size of one record.
        window_bytes: The scanned tail budget.

    Returns:
        ``window_bytes // record_bytes``, floored at 0.
    """
    size = _check_positive_int(record_bytes, "record_bytes")
    window = _check_positive_int(window_bytes, "window_bytes")
    return window // size


def capacity_report(
    base_record_bytes: int,
    *,
    window_bytes: int = DEFAULT_NONCE_WINDOW_BYTES,
) -> CapacityReport:
    """Compare unsigned and signed record capacity in the nonce tail.

    The reference manual notes that a room of short signed messages
    "fits roughly a third fewer records into the scanned window". That
    ratio is not a constant — it depends on the unsigned record size —
    so this report computes it from a caller-supplied base size rather
    than hard-coding it.

    Args:
        base_record_bytes: Size of an unsigned record of this shape,
            including its terminating newline if the caller's source
            counts one.
        window_bytes: The scanned tail budget.

    Returns:
        A :class:`CapacityReport`.
    """
    base = _check_positive_int(base_record_bytes, "base_record_bytes")
    window = _check_positive_int(window_bytes, "window_bytes")
    signed_size = signed_record_bytes(base)
    unsigned_records = records_in_window(base, window)
    signed_records = records_in_window(signed_size, window)
    lost = unsigned_records - signed_records
    fraction = (lost / unsigned_records) if unsigned_records else 0.0
    return CapacityReport(
        window_bytes=window,
        base_record_bytes=base,
        signed_record_bytes=signed_size,
        unsigned_records=unsigned_records,
        signed_records=signed_records,
        records_lost=lost,
        fraction_lost=fraction,
    )


def _coerce_entry(entry: Any, index: int) -> WindowEntry:
    """Normalize one caller-supplied entry to a :class:`WindowEntry`.

    Accepts a :class:`WindowEntry`, a mapping, or any object with a
    ``size_bytes`` attribute. ``did`` is read before ``from`` because
    the read API reports the full DID in ``from``; an unsigned record's
    ``from`` is a self-asserted nickname, so a nickname is never
    promoted to an identity — see :func:`classify_window`.
    """
    if isinstance(entry, WindowEntry):
        size, seq, did, nonce = (
            entry.size_bytes,
            entry.seq,
            entry.did,
            entry.nonce,
        )
    elif isinstance(entry, Mapping):
        size = entry.get("size_bytes")
        seq = entry.get("seq")
        did = entry.get("did")
        if did is None:
            did = entry.get("from")
        nonce = entry.get("nonce")
    elif hasattr(entry, "size_bytes"):
        size = getattr(entry, "size_bytes")
        seq = getattr(entry, "seq", None)
        did = getattr(entry, "did", None)
        if did is None:
            did = getattr(entry, "from", None)
        nonce = getattr(entry, "nonce", None)
    else:
        raise NonceWindowError(
            f"entry {index} must be a WindowEntry, mapping, or object "
            "with a size_bytes attribute"
        )

    if isinstance(size, bool) or not isinstance(size, int):
        raise NonceWindowError(f"entry {index} size_bytes must be an int")
    if size <= 0:
        raise NonceWindowError(f"entry {index} size_bytes must be positive")

    if seq is not None and (isinstance(seq, bool) or not isinstance(seq, int)):
        raise NonceWindowError(f"entry {index} seq must be an int or None")
    if did is not None and not isinstance(did, str):
        raise NonceWindowError(f"entry {index} did must be a str or None")

    if nonce is not None and not isinstance(nonce, str):
        # The read API returns the nonce as an integer, and a 19-digit
        # value does not survive a float. Accept int, reject float and
        # bool, so a precision loss can never enter the report silently.
        if isinstance(nonce, bool):
            raise NonceWindowError(
                f"entry {index} nonce must be a decimal str or int, "
                "not a bool"
            )
        if isinstance(nonce, int):
            nonce = str(nonce)
        else:
            raise NonceWindowError(
                f"entry {index} nonce must be a decimal str or int, "
                f"not {type(nonce).__name__}"
            )

    return WindowEntry(size_bytes=size, seq=seq, did=did, nonce=nonce)


def classify_window(
    entries: Sequence[Any],
    *,
    window_bytes: int = DEFAULT_NONCE_WINDOW_BYTES,
    did: Optional[str] = None,
) -> WindowReport:
    """Classify records against the documented 1 MiB nonce tail.

    ``entries`` must be in room order, oldest first, which is the order
    both ``GET /r/<room>`` and ``GET /r/<room>/export`` return. Walking
    backwards from the newest, the window holds every record whose
    cumulative byte cost stays within ``window_bytes``; everything
    before that has been buried past the tail by newer traffic.

    The boundary is modelled as inclusive — a record whose cumulative
    size equals ``window_bytes`` exactly is counted as still inside.
    The manual does not publish the server's inclusive/exclusive rule,
    so the inclusive reading is the conservative one: it reports a
    record as protected for slightly longer than an exclusive reading
    would. See ``docs/nonce-window.md``.

    Args:
        entries: Records in room order, oldest first. Each must carry a
            positive ``size_bytes``; ``seq``, ``did``/``from``, and
            ``nonce`` are optional.
        window_bytes: The scanned tail budget.
        did: Restrict the signer verdict to one DID.

    Returns:
        A :class:`WindowReport`.

    Raises:
        NonceWindowError: On malformed input, an empty ``entries``, or a
            non-string ``did``.
    """
    window = _check_positive_int(window_bytes, "window_bytes")
    if isinstance(entries, (str, bytes, bytearray)):
        raise NonceWindowError("entries must be a sequence of records")
    try:
        raw = list(entries)
    except TypeError as exc:
        raise NonceWindowError("entries must be a sequence of records") from exc
    if not raw:
        raise NonceWindowError("entries must contain at least one record")
    if did is not None and not isinstance(did, str):
        raise NonceWindowError("did must be a str or None")

    items = [_coerce_entry(entry, i) for i, entry in enumerate(raw)]

    total_bytes = 0
    for item in items:
        total_bytes += item.size_bytes

    # Walk backwards from the newest, accumulating until the budget is
    # exhausted. ``cut`` is the index of the oldest still-inside record.
    accumulated = 0
    cut = len(items)
    for i in range(len(items) - 1, -1, -1):
        size = items[i].size_bytes
        if accumulated + size > window:
            break
        accumulated += size
        cut = i

    inside = items[cut:]
    expired = items[:cut]
    in_window_bytes = sum(item.size_bytes for item in inside)
    expired_bytes = total_bytes - in_window_bytes

    did_in_window = 0
    did_expired = 0
    did_last_nonce = None
    anonymous = 0
    if did is not None:
        # `inside` is oldest-first, so iterating it forward and keeping
        # the last match yields the newest nonce the server can see.
        for item in inside:
            if item.did is None:
                anonymous += 1
            elif item.did == did:
                did_in_window += 1
                if item.nonce is not None:
                    did_last_nonce = item.nonce
        did_expired = sum(1 for item in expired if item.did == did)
    else:
        anonymous = sum(1 for item in inside if item.did is None)

    protected = did_in_window > 0
    if did is None:
        reason = None
    elif protected:
        reason = (
            "server can still see a nonce for this key in the scanned "
            "tail; the strictly increasing check has a reference point"
        )
    elif did_expired:
        reason = (
            "every record for this key has been buried past the "
            "scanned tail; a captured signed URL for this key can be "
            "accepted again while the signature still proves authorship"
        )
    else:
        reason = "no record for this key was supplied"

    return WindowReport(
        window_bytes=window,
        total_records=len(items),
        total_bytes=total_bytes,
        in_window_records=len(inside),
        in_window_bytes=in_window_bytes,
        expired_records=len(expired),
        expired_bytes=expired_bytes,
        oldest_protected_seq=inside[0].seq if inside else None,
        newest_expired_seq=expired[-1].seq if expired else None,
        did=did,
        did_in_window_records=did_in_window,
        did_expired_records=did_expired,
        did_last_nonce_in_window=did_last_nonce,
        did_last_seen_protected=protected,
        records_without_identity=anonymous,
        reason=reason,
    )