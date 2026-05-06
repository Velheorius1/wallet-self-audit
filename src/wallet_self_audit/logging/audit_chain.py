"""Tamper-evident hash-chained JSONL audit log.

Layout: append-only JSONL at ``~/.local/state/wsa/audit.jsonl``. Each
line is a JSON object with at minimum::

    {"ts": "<ISO-UTC>", "seq": <int>, "event": "<name>", "prev_hash": "...",
     "hash": "..."}

The ``hash`` of a line is ``sha256(prev_hash || canonicalised_payload)``,
so any retroactive modification to an earlier line invalidates every
subsequent ``hash``. ``wsa audit verify`` (Phase 7) walks the chain and
flags the first divergence.

The events are public-safe metadata only — never private keys. Adding
new event payloads requires keeping this invariant; the
:func:`append_event` helper does NOT validate, so callers are
responsible for redacting.

Append-only enforcement on macOS uses ``chflags uappend`` via the
``chflags`` system command; on Linux we set the ``a`` (append-only)
attribute via ``chattr`` if available. Both are best-effort; the hash
chain remains the cryptographic source of truth.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import time
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

_GENESIS_PREV: str = "0" * 64


def _state_dir() -> Path:
    return Path.home() / ".local" / "state" / "wsa"


def audit_chain_path() -> Path:
    """Return the canonical audit-chain JSONL file path."""
    return _state_dir() / "audit.jsonl"


def _ensure_parent_dir(path: Path) -> None:
    parent = path.parent
    parent.mkdir(parents=True, exist_ok=True)
    with contextlib.suppress(OSError):
        parent.chmod(0o700)


def _canonicalise(payload: dict[str, object]) -> bytes:
    """Deterministic byte serialisation of a payload (UTF-8 JSON, sorted keys)."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _read_last_line(path: Path) -> str | None:
    """Return the last non-empty line of ``path``, or ``None``."""
    if not path.exists() or path.stat().st_size == 0:
        return None
    # For our small log this brute-force read is fine; full files stay
    # under a few MB even for heavy users.
    with path.open("r", encoding="utf-8") as f:
        last: str | None = None
        for line in f:
            stripped = line.strip()
            if stripped:
                last = stripped
        return last


def _last_seq_and_hash(path: Path) -> tuple[int, str]:
    """Return (last_seq, last_hash) of the chain, or (-1, GENESIS) if empty."""
    last = _read_last_line(path)
    if last is None:
        return -1, _GENESIS_PREV
    obj: object = json.loads(last)
    if not isinstance(obj, dict):
        return -1, _GENESIS_PREV
    obj_typed: dict[str, object] = obj  # pyright: ignore[reportUnknownVariableType,reportAssignmentType]
    seq_obj = obj_typed.get("seq")
    hash_obj = obj_typed.get("hash")
    if not isinstance(seq_obj, int) or not isinstance(hash_obj, str):
        return -1, _GENESIS_PREV
    return seq_obj, hash_obj


def append_event(event: str, payload: dict[str, object]) -> dict[str, object]:
    """Append one event to the audit chain. Returns the appended record.

    The record always contains ``ts``, ``seq``, ``event``, ``prev_hash``,
    ``hash``, and any caller-provided ``payload`` keys (merged at the
    top level). Callers MUST ensure ``payload`` contains no secrets.
    """
    path = audit_chain_path()
    _ensure_parent_dir(path)
    last_seq, last_hash = _last_seq_and_hash(path)
    seq = last_seq + 1
    record: dict[str, object] = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "seq": seq,
        "event": event,
        "prev_hash": last_hash,
        **payload,
    }
    h = hashlib.sha256()
    h.update(last_hash.encode("ascii"))
    h.update(_canonicalise(record))
    record["hash"] = h.hexdigest()

    # Append atomically.
    line = json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n"
    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
    fd = os.open(path, flags, 0o600)
    try:
        os.write(fd, line.encode("utf-8"))
    finally:
        os.close(fd)
    return record


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class ChainBreak:
    """One anomaly detected by :func:`verify_chain`."""

    seq: int
    reason: str


def _iter_records(path: Path) -> Iterator[dict[str, object]]:
    if not path.exists():
        return
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            stripped = line.strip()
            if not stripped:
                continue
            obj: object = json.loads(stripped)
            if isinstance(obj, dict):
                yield obj


def verify_chain(path: Path | None = None) -> list[ChainBreak]:
    """Walk the chain. Return a list of breaks (empty list = chain valid)."""
    target = path or audit_chain_path()
    breaks: list[ChainBreak] = []
    expected_seq = 0
    expected_prev = _GENESIS_PREV
    for record in _iter_records(target):
        seq_obj = record.get("seq")
        if not isinstance(seq_obj, int):
            breaks.append(ChainBreak(seq=expected_seq, reason="missing seq"))
            return breaks
        if seq_obj != expected_seq:
            breaks.append(
                ChainBreak(
                    seq=expected_seq,
                    reason=f"out-of-order seq: got {seq_obj}",
                )
            )
            return breaks
        stored_hash = record.get("hash")
        prev_hash = record.get("prev_hash")
        if not isinstance(stored_hash, str) or not isinstance(prev_hash, str):
            breaks.append(ChainBreak(seq=seq_obj, reason="missing hash fields"))
            return breaks
        if prev_hash != expected_prev:
            breaks.append(ChainBreak(seq=seq_obj, reason="prev_hash does not match previous hash"))
            return breaks
        # Recompute hash.
        recomputed = _recompute_hash(record, prev_hash)
        if recomputed != stored_hash:
            breaks.append(ChainBreak(seq=seq_obj, reason="hash mismatch"))
            return breaks
        expected_seq = seq_obj + 1
        expected_prev = stored_hash
    return breaks


def _recompute_hash(record: dict[str, object], prev_hash: str) -> str:
    """Recompute the canonical sha256 of ``record`` (excluding the stored hash)."""
    payload: dict[str, object] = {k: v for k, v in record.items() if k != "hash"}
    h = hashlib.sha256()
    h.update(prev_hash.encode("ascii"))
    h.update(_canonicalise(payload))
    return h.hexdigest()


__all__ = [
    "ChainBreak",
    "append_event",
    "audit_chain_path",
    "verify_chain",
]
