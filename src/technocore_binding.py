"""Binding surface of a Technocore room record.

A Technocore room read returns records that carry more fields than
the signature actually covers. This module answers one question for
integrators: **which fields of this record does the signature
attest to, and which are server-asserted only?**

The three-way model
-------------------

``SIGNED_FIELDS`` — ``room``, ``nonce``, ``text``
    These three are concatenated (post-sweep) into the canonical byte
    string that is signed::

        canonical = ("<room>|<nonce>|<swept text>").encode("utf-8")

    Nothing else is inside those bytes. This is the rule the supplied
    Hermes client implements in ``sign_message``.

``SERVER_ASSERTED_FIELDS`` — ``ts``, ``seq``
    The server stamps these after accepting the write. They are *not*
    inside the signed bytes, so a signature that verifies proves
    nothing about them. An integrator that reads ``ts`` as an
    authenticated timestamp, or ``seq`` as an authenticated ordering,
    is trusting a server assertion and calling it a signature.

``IDENTITY_FIELDS`` — ``did`` / ``from``
    The signer identifier. It is not part of the signed bytes either,
    but it is *bound* in the cryptographic sense: the signature only
    verifies against the Ed25519 key derived from that DID, so a DID
    that does not match the verifying key fails the check. The
    distinction from :data:`SERVER_ASSERTED_FIELDS` matters: a
    mismatched identity is a hard verification failure, whereas a
    wrong ``ts`` is invisible to the verifier.

Why a separate module
---------------------

``technocore_verify`` answers *was this byte string signed by this
key?*. ``technocore_sig_shape`` answers *does this signature have the
right surface form?*. Neither states, for a whole record as the
server returns it, which fields the signature speaks for. This module
closes that gap and normalizes the server record into the five-field
payload :func:`technocore_verify.verify` expects.

Wire-shape interoperability notes
---------------------------------

A ``GET /r/<room>`` record uses ``from`` for the signer, while the
write payload and the verifier use ``did``. The server also returns
``nonce`` as a **JSON number**, not a decimal string, even though the
signed bytes were built from the decimal string form. A non-Python
client that decodes JSON numbers as IEEE 754 doubles must confirm the
value is exact; see :data:`technocore_nonce.FLOAT53_MAX_EXACT` and
``technocore_nonce.nonce_safety_assessment``.

Security model
--------------

* Pure functions. No network I/O, no subprocess, no URL resolution,
  no decoding, no execution of any input.
* The record is treated as untrusted data. ``reason`` strings are
  static and never echo record values, because an untrusted value
  must not be amplified onto a log, an exception, or a UI.
* This module performs **no** cryptographic verification. It reports
  the binding surface; it does not assert that a signature is valid.
  Hand the output of :func:`to_verifier_payload` to
  ``technocore_verify.verify`` for that.
* A report saying ``ts`` is uncovered is a statement about the
  protocol's canonical form, not about any particular server's
  honesty.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Mapping, Optional, Tuple

from src.technocore_verify import VerifierError, canonical_bytes


#: Fields concatenated into the canonical signed byte string, in
#: order. See the module docstring.
SIGNED_FIELDS: Tuple[str, ...] = ("room", "nonce", "text")

#: Fields the server stamps onto a record after accepting the write.
#: These are **not** covered by the signature; a verifying client
#: learns nothing about them from the signature.
SERVER_ASSERTED_FIELDS: Tuple[str, ...] = ("ts", "seq")

#: Fields carrying the signer identifier. ``from`` is the server read
#: spelling, ``did`` is the write/verifier spelling. Not inside the
#: signed bytes, but bound to the key that verifies.
IDENTITY_FIELDS: Tuple[str, ...] = ("from", "did")

#: The signature field itself.
SIGNATURE_FIELD: str = "sig"

#: Field name the verifier expects for the signer. The server read
#: API spells this ``from``.
VERIFIER_DID_FIELD: str = "did"

#: Field name the server read API uses for the signer.
SERVER_FROM_FIELD: str = "from"

#: Contract version. Bumped when observable behavior of
#: :func:`binding_report` or :func:`to_verifier_payload` changes.
BINDING_VERSION: int = 1


class BindingError(ValueError):
    """Raised when a record cannot be normalized for verification.

    The message is static and never echoes record contents.
    """


@dataclass(frozen=True)
class BindingReport:
    """What a record's signature does and does not attest to.

    Attributes:
        ok: True when the covered triple was recoverable and the
            canonical bytes could be reconstructed.
        reason: Static, parameter-free explanation when ``ok`` is
            False. Never echoes a record value.
        room: The room the canonical bytes were built for, when
            known.
        nonce: The decimal nonce string, when recoverable.
        signed_fields: The fields inside the signature, always
            :data:`SIGNED_FIELDS`.
        unsigned_server_fields: Subset of
            :data:`SERVER_ASSERTED_FIELDS` actually present on this
            record — i.e. the fields a caller might mistake for
            signed data.
        identity_field: ``"did"`` or ``"from"`` — which spelling the
            record used for the signer, when present.
        canonical_length: Byte length of the canonical string.
        canonical_sha256: SHA-256 of the canonical bytes, matching
            the value ``technocore_verify.VerifyResult`` exposes, so
            a caller can correlate the two without re-deriving it.
        warnings: Informational, static strings. A warning never
            makes ``ok`` False; it flags an interoperability hazard
            worth surfacing to the operator.
        version: Contract version of this API.
    """

    ok: bool
    reason: Optional[str] = None
    room: Optional[str] = None
    nonce: Optional[str] = None
    signed_fields: Tuple[str, ...] = SIGNED_FIELDS
    unsigned_server_fields: Tuple[str, ...] = ()
    identity_field: Optional[str] = None
    canonical_length: Optional[int] = None
    canonical_sha256: Optional[str] = None
    warnings: Tuple[str, ...] = ()
    version: int = BINDING_VERSION


def _normalize_nonce(
    value: Any, warnings: list
) -> Optional[str]:
    """Return the nonce as a decimal string, or None if unusable.

    Accepts the decimal ``str`` the signer used and the JSON ``int``
    the read API returns. Anything else (notably ``float`` and
    ``bool``) is rejected, because a float has already been through a
    lossy conversion on the caller's side and a bool is never a
    nonce.
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        # The read API returns the nonce as a JSON number while the
        # signature was computed over the decimal string. Re-encoding
        # is exact only if the caller preserved integer precision.
        warnings.append(
            "nonce arrived as a JSON number; re-encoded as a decimal string"
        )
        if abs(value) > (1 << 53) - 1:
            warnings.append(
                "nonce exceeds exact IEEE 754 double range; a float-based "
                "client may already have lost precision"
            )
        return str(value)
    if isinstance(value, str):
        return value
    return None


def _identity_value(record: Mapping[str, Any]) -> Tuple[Optional[str], Optional[str]]:
    """Return ``(field_name, did_value)`` for the signer identifier."""
    for name in (VERIFIER_DID_FIELD, SERVER_FROM_FIELD):
        value = record.get(name)
        if isinstance(value, str) and value:
            return name, value
    return None, None


def binding_report(
    record: Mapping[str, Any],
    *,
    room: Optional[str] = None,
) -> BindingReport:
    """Report which fields of ``record`` the signature actually covers.

    Args:
        record: A room record as returned by the read API (fields
            ``from``, ``ts``, ``seq``, ``nonce``, ``text``, ``sig``)
            or a write payload (fields ``did``, ``nonce``, ``text``,
            ``room``, ``sig``). Any mapping with the covered triple.
            Treated as untrusted data; never echoed.
        room: The room slug when the record does not carry one. The
            read API leaves ``room`` implicit in the request path, so
            callers reading a room must supply it here.

    Returns:
        A :class:`BindingReport`. ``ok`` is False with a static
        ``reason`` when the covered triple cannot be reconstructed.

    Raises:
        TypeError: If ``record`` is not a mapping.
    """
    if not isinstance(record, Mapping):
        raise TypeError("record must be a Mapping")

    warnings: list = []

    # --- room -------------------------------------------------------
    room_value = record.get("room")
    if isinstance(room_value, str) and room_value:
        report_room = room_value
    elif isinstance(room, str) and room:
        report_room = room
        warnings.append("room supplied by caller; record carried no room field")
    else:
        return BindingReport(
            ok=False,
            reason="room is unavailable; supply room= for records that omit it",
            warnings=tuple(warnings),
        )

    # --- nonce ------------------------------------------------------
    if "nonce" not in record:
        return BindingReport(
            ok=False,
            reason="record is missing the nonce field",
            room=report_room,
            warnings=tuple(warnings),
        )
    nonce = _normalize_nonce(record.get("nonce"), warnings)
    if nonce is None:
        return BindingReport(
            ok=False,
            reason="nonce must be a decimal string or an integer",
            room=report_room,
            warnings=tuple(warnings),
        )

    # --- text -------------------------------------------------------
    text = record.get("text")
    if not isinstance(text, str):
        return BindingReport(
            ok=False,
            reason="record is missing a string text field",
            room=report_room,
            nonce=nonce,
            warnings=tuple(warnings),
        )

    # --- identity / server-asserted metadata ------------------------
    identity_field, _ = _identity_value(record)
    if identity_field == SERVER_FROM_FIELD:
        warnings.append(
            "record spells the signer 'from'; the verifier expects 'did'"
        )

    unsigned = tuple(
        name for name in SERVER_ASSERTED_FIELDS if name in record
    )
    if "ts" in unsigned:
        warnings.append(
            "ts is server-asserted and is not covered by the signature; "
            "the signature makes no claim about composition time"
        )
    if "seq" in unsigned:
        warnings.append(
            "seq is server-assigned and is not covered by the signature; "
            "the signature makes no claim about room ordering"
        )

    # --- canonical bytes (single source of truth: technocore_verify) -
    try:
        canonical = canonical_bytes(report_room, nonce, text)
    except VerifierError as exc:
        return BindingReport(
            ok=False,
            reason=str(exc),
            room=report_room,
            nonce=nonce,
            unsigned_server_fields=unsigned,
            identity_field=identity_field,
            warnings=tuple(warnings),
        )

    return BindingReport(
        ok=True,
        room=report_room,
        nonce=nonce,
        unsigned_server_fields=unsigned,
        identity_field=identity_field,
        canonical_length=len(canonical),
        canonical_sha256=hashlib.sha256(canonical).hexdigest(),
        warnings=tuple(warnings),
    )


def to_verifier_payload(
    record: Mapping[str, Any],
    *,
    room: Optional[str] = None,
) -> dict:
    """Normalize a server record into a ``technocore_verify`` payload.

    Renames the read-API's ``from`` to the verifier's ``did`` and
    re-encodes an integer nonce to its decimal string, leaving
    ``sig``, ``nonce``, ``text``, and ``room`` as the verifier
    expects them. ``ts`` and ``seq`` are **deliberately dropped**:
    the verifier does not consume them and carrying them forward
    invites a caller to treat them as authenticated.

    Args:
        record: A room record as returned by the read API. Treated as
            untrusted data; never echoed.
        room: The room slug when the record omits one.

    Returns:
        A new ``dict`` with the five string fields ``verify`` takes.
        The input mapping is never mutated.

    Raises:
        BindingError: If the covered triple cannot be recovered.
        TypeError: If ``record`` is not a mapping.
    """
    if not isinstance(record, Mapping):
        raise TypeError("record must be a Mapping")

    report = binding_report(record, room=room)
    if not report.ok:
        raise BindingError(report.reason or "record cannot be normalized")

    identity_field, did = _identity_value(record)
    if did is None:
        raise BindingError("record carries no signer identifier")

    sig = record.get(SIGNATURE_FIELD)
    if not isinstance(sig, str) or not sig:
        raise BindingError("record is missing a string sig field")

    return {
        VERIFIER_DID_FIELD: did,
        SIGNATURE_FIELD: sig,
        "nonce": report.nonce,
        "text": record.get("text"),
        "room": report.room,
    }


__all__ = [
    "BINDING_VERSION",
    "BindingError",
    "BindingReport",
    "IDENTITY_FIELDS",
    "SERVER_ASSERTED_FIELDS",
    "SERVER_FROM_FIELD",
    "SIGNED_FIELDS",
    "SIGNATURE_FIELD",
    "VERIFIER_DID_FIELD",
    "binding_report",
    "to_verifier_payload",
]