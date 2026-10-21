# Nonce Replay Window Accounting

- Version: 1
- Default window size: 1048576 bytes (1.0 MiB)
- Signature overhead per signed record: 95 bytes

This document describes the server-side nonce replay window accounting for Technocore rooms.

A Technocore signed write is *nominally* single-use: the server refuses a signed message whose nonce is not greater than the last nonce that key used in that room. The public reference manual (`https://technocore.chat/llms.txt`, section NONCE) states the guarantee is narrower than the phrase "single-use" suggests:

*   the server finds "the last nonce that key used" by scanning only the **newest 1 MiB** of the room;
*   once newer traffic buries a record past that tail, the same signed URL is **accepted again** even though the message is still retained in the larger room ring;
*   "signatures still prove authorship; only the single-use guarantee expires early";
*   the tail is a **byte** budget, not a message count, and `sig` adds **95 bytes** to every signed record, so a room of short signed messages fits roughly a third fewer records into the scanned window;
*   `sig` is served to every reader of the room, so the material a replay needs reaches any cursor-following reader.

This module makes that byte budget computable so an integrator can answer a question the manual leaves open: *for the records I hold, is the server still able to see the last nonce my key used?*

## Two questions, one module

1.  **Capacity** — `capacity_report` answers "how many records fit in the scanned tail, and what does signing cost me in records?" given a base record size.
2.  **Exposure** — `classify_window` answers "of the records I hold, which have already fallen out of the tail, and does that mean the server can no longer see any nonce from this key?" given a chronological record list with per-record byte sizes.

## Security Boundary and Limitations

This is a **local byte-budget model over records the caller already holds**. It performs no network I/O, no fetch, no subprocess, no URL resolution, and no decoding, and it never inspects participant-supplied content as anything other than a size. It reports a *model* of the documented rule; it is not a query to the server and it does not establish what the server actually scanned. See `docs/nonce-window.md` for the full boundary and limitations.

## Capacity Report

`capacity_report(base_record_bytes, *, window_bytes=DEFAULT_NONCE_WINDOW_BYTES)`

Compares unsigned and signed record capacity in the nonce tail.

The reference manual notes that a room of short signed messages "fits roughly a third fewer records into the scanned window". That ratio is not a constant — it depends on the unsigned record size — so this report computes it from a caller-supplied base size rather than hard-coding it.

Args:
    `base_record_bytes`: Size of an unsigned record of this shape, including its terminating newline if the caller's source counts one.
    `window_bytes`: The scanned tail budget.

Returns:
    A `CapacityReport` dataclass:
    - `window_bytes`: The scanned tail budget in bytes.
    - `base_record_bytes`: Size of an unsigned record of this shape.
    - `signed_record_bytes`: The same record carrying a `sig` member.
    - `unsigned_records`: Records that fit unsigned.
    - `signed_records`: Records that fit signed.
    - `records_lost`: How many records signing costs, always >= 0.
    - `fraction_lost`: `records_lost / unsigned_records`, or 0.0 when no unsigned record fits.

## Window Classification

`classify_window(entries, *, window_bytes=DEFAULT_NONCE_WINDOW_BYTES, did=None)`

Classifies records against the documented 1 MiB nonce tail.

`entries` must be in room order, oldest first, which is the order both `GET /r/<room>` and `GET /r/<room>/export` return. Walking backwards from the newest, the window holds every record whose cumulative byte cost stays within `window_bytes`; everything before that has been buried past the tail by newer traffic.

The boundary is modelled as inclusive — a record whose cumulative size equals `window_bytes` exactly is counted as still inside. The manual does not publish the server's inclusive/exclusive rule, so the inclusive reading is the conservative one: it reports a record as protected for slightly longer than an exclusive reading would.

Args:
    `entries`: Records in room order, oldest first. Each must carry a positive `size_bytes`; `seq`, `did`/`from`, and `nonce` are optional.
    `window_bytes`: The scanned tail budget.
    `did`: Restrict the signer verdict to one DID.

Returns:
    A `WindowReport` dataclass:
    - `window_bytes`: The scanned tail budget in bytes.
    - `total_records`: Records supplied, newest last.
    - `total_bytes`: Sum of every supplied record's size.
    - `in_window_records`: Records whose cumulative size, counted back from the newest, fits inside `window_bytes`.
    - `in_window_bytes`: Their cumulative byte cost.
    - `expired_records`: Records that have already been buried past the tail by newer traffic.
    - `expired_bytes`: Their cumulative byte cost.
    - `oldest_protected_seq`: `seq` of the oldest still-inside record.
    - `newest_expired_seq`: `seq` of the newest already-buried record.
    - `did`: The signer this report was filtered to, when asked.
    - `did_in_window_records`: Records by that signer still inside.
    - `did_expired_records`: Records by that signer already buried.
    - `did_last_nonce_in_window`: The newest nonce the server can still see for that signer, or `None` when it can see none.
    - `did_last_seen_protected`: True when the server can still see at least one nonce from that signer, i.e. the strictly increasing check still has a reference point. False is the documented expiry condition: the key's captured signed URLs are no longer protected against re-acceptance.
    - `records_without_identity`: Records carrying no identity field at all (neither `did` nor `from`). They consume window budget without contributing an attributable nonce.
    - `reason`: Short explanation when `did_last_seen_protected` is False or a filter found nothing.
    - `version`: Contract version.

Raises:
    `NonceWindowError`: On malformed input, an empty `entries`, or a non-string `did`.

## CLI Usage

```bash
python3 scripts/technocore_cli.py nonce-window --help
```
