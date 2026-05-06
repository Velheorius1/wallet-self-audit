"""SQLite wrapper for per-audit caches.

Layout: one DB file per audit at
``~/.local/share/wsa/audits/<audit_id>/cache.db``. The DB stores raw
transactions, parsed signature records, address↔pubkey mappings, and
findings. Sensitive (per-audit) data lives only here, with its own file
permissions (mode 0o600 on the directory).

Hand-rolled migration via ``PRAGMA user_version``. Phase 6 ships
schema v1; future schema bumps add a stub migration in ``_MIGRATIONS``.

API:
- :func:`open_db(audit_id)` opens (creates if needed) the per-audit DB
  with foreign keys + WAL mode and the schema applied.
- :func:`record_audit_start` / :func:`record_audit_finish` track the
  audit lifecycle in the ``audits`` table.
- :func:`insert_signatures` bulk-inserts ``SignatureRecord``s.
- :func:`record_finding` writes one finding row.

We do NOT use SQLCipher here in v1.0 — encryption is deferred to v1.1
(the audit DB contains only public chain data plus public fingerprints
of findings, no secrets).
"""

from __future__ import annotations

import contextlib
import json
import sqlite3
import time
from collections.abc import Generator, Iterable
from contextlib import contextmanager
from pathlib import Path
from typing import Final

from wallet_self_audit.nonce.extractor import SignatureRecord
from wallet_self_audit.verdict import VerdictWithoutKey

_SCHEMA_PATH: Final[Path] = Path(__file__).resolve().parent / "schema.sql"
_TARGET_SCHEMA_VERSION: Final[int] = 1


def _data_dir() -> Path:
    """XDG-style location for per-audit databases."""
    return Path.home() / ".local" / "share" / "wsa" / "audits"


def _ensure_per_audit_dir(audit_id: str) -> Path:
    """Create the per-audit directory with mode 0o700 if missing."""
    base = _data_dir() / audit_id
    base.mkdir(parents=True, exist_ok=True)
    # Some filesystems (FAT-mounted USBs etc.) ignore chmod. Best-effort.
    with contextlib.suppress(OSError):
        base.chmod(0o700)
    return base


def db_path(audit_id: str) -> Path:
    """Return the SQLite file path for the given audit_id."""
    return _ensure_per_audit_dir(audit_id) / "cache.db"


@contextmanager
def open_db(audit_id: str) -> Generator[sqlite3.Connection, None, None]:
    """Yield a connection with schema applied. Closes on exit.

    Use as ``with open_db(audit_id) as conn: ...``. The connection has
    foreign keys enabled and uses WAL mode for crash safety.
    """
    path = db_path(audit_id)
    conn = sqlite3.connect(path)
    try:
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        _apply_schema(conn)
        yield conn
    finally:
        conn.close()


def _apply_schema(conn: sqlite3.Connection) -> None:
    """Apply schema.sql if user_version < target."""
    cur = conn.execute("PRAGMA user_version")
    row = cur.fetchone()
    current = int(row[0]) if row else 0
    if current >= _TARGET_SCHEMA_VERSION:
        return
    sql = _SCHEMA_PATH.read_text(encoding="utf-8")
    conn.executescript(sql)
    conn.commit()


# ---------------------------------------------------------------------------
# Audit lifecycle
# ---------------------------------------------------------------------------
def record_audit_start(
    conn: sqlite3.Connection,
    *,
    audit_id: str,
    address: str,
    toolkit_version: str,
    ownership_proof_hash: str,
) -> None:
    """Insert a row in ``audits`` with status='running'."""
    conn.execute(
        "INSERT OR REPLACE INTO audits "
        "(audit_id, address, started_at, finished_at, toolkit_version, "
        " ownership_proof_hash, status) "
        "VALUES (?, ?, ?, NULL, ?, ?, 'running')",
        (audit_id, address, int(time.time()), toolkit_version, ownership_proof_hash),
    )
    conn.commit()


def record_audit_finish(
    conn: sqlite3.Connection,
    *,
    audit_id: str,
    verdict: VerdictWithoutKey,
) -> None:
    """Update the ``audits`` row with the final verdict status."""
    status_map = {
        "SAFE": "safe",
        "SUSPICIOUS": "suspicious",
        "VULNERABLE": "vulnerable",
    }
    status = status_map.get(verdict.status, "error")
    conn.execute(
        "UPDATE audits SET finished_at = ?, status = ? WHERE audit_id = ?",
        (int(time.time()), status, audit_id),
    )
    conn.commit()


# ---------------------------------------------------------------------------
# Signature ingestion
# ---------------------------------------------------------------------------
def insert_signatures(
    conn: sqlite3.Connection,
    records: Iterable[SignatureRecord],
) -> int:
    """Bulk-insert SignatureRecords (and parent transaction stubs).

    For each unique ``txid`` we first ``INSERT OR IGNORE`` a placeholder
    row in ``transactions`` so the foreign key on ``signatures.txid``
    holds. Callers can later upgrade that placeholder via a separate
    UPDATE if they have the raw hex.

    Returns the number of signature rows written.
    """
    sig_rows: list[tuple[str, int, str, bytes, bytes, bytes, int, str]] = []
    tx_rows: list[tuple[str, int]] = []
    seen_txids: set[str] = set()
    fetched_at = int(time.time())
    for rec in records:
        if rec.txid not in seen_txids:
            tx_rows.append((rec.txid, fetched_at))
            seen_txids.add(rec.txid)
        z_bytes = rec.z.to_bytes(32, "big") if rec.z else b""
        sig_rows.append(
            (
                rec.txid,
                rec.vin_index,
                rec.pubkey_compressed.hex(),
                rec.r.to_bytes(32, "big"),
                rec.s.to_bytes(32, "big"),
                z_bytes,
                rec.sighash_type,
                rec.script_type,
            )
        )

    conn.executemany(
        "INSERT OR IGNORE INTO transactions (txid, fetched_at) VALUES (?, ?)",
        tx_rows,
    )
    conn.executemany(
        "INSERT OR REPLACE INTO signatures "
        "(txid, vin_index, pubkey_hex, r, s, z, sighash_type, script_type) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        sig_rows,
    )
    conn.commit()
    return len(sig_rows)


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------
def record_finding(
    conn: sqlite3.Connection,
    *,
    audit_id: str,
    severity: str,
    kind: str,
    pubkey_hex: str | None,
    payload: dict[str, object],
) -> None:
    """Append a finding row.

    ``payload`` is serialized to JSON. It MUST NOT contain any private-
    key material — this is the same surface we expose in reports.
    """
    conn.execute(
        "INSERT INTO findings (audit_id, severity, kind, pubkey_hex, payload_json) "
        "VALUES (?, ?, ?, ?, ?)",
        (audit_id, severity, kind, pubkey_hex, json.dumps(payload, sort_keys=True)),
    )
    conn.commit()


def get_findings(conn: sqlite3.Connection, audit_id: str) -> list[dict[str, object]]:
    """Return all findings for an audit, decoded from JSON."""
    cur = conn.execute(
        "SELECT severity, kind, pubkey_hex, payload_json FROM findings "
        "WHERE audit_id = ? ORDER BY finding_id",
        (audit_id,),
    )
    out: list[dict[str, object]] = []
    for severity, kind, pubkey_hex, payload_json in cur.fetchall():
        payload_obj: object = json.loads(payload_json)
        if not isinstance(payload_obj, dict):
            continue
        payload: dict[str, object] = payload_obj  # pyright: ignore[reportUnknownVariableType,reportAssignmentType]
        out.append(
            {
                "severity": severity,
                "kind": kind,
                "pubkey_hex": pubkey_hex,
                "payload": payload,
            }
        )
    return out


__all__ = [
    "db_path",
    "get_findings",
    "insert_signatures",
    "open_db",
    "record_audit_finish",
    "record_audit_start",
    "record_finding",
]
