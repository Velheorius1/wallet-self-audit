"""Unit tests for the SQLite storage wrapper."""

from __future__ import annotations

from pathlib import Path

import pytest

from wallet_self_audit.nonce.extractor import SignatureRecord
from wallet_self_audit.storage import db as storage_db
from wallet_self_audit.storage.db import (
    db_path,
    get_findings,
    insert_signatures,
    open_db,
    record_audit_finish,
    record_audit_start,
    record_finding,
)
from wallet_self_audit.verdict import VerdictWithoutKey


@pytest.fixture
def isolated_data_dir(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    """Redirect the data dir under tmp so tests never touch ~/.local."""
    monkeypatch.setattr(storage_db, "_data_dir", lambda: tmp_path / "audits")
    return tmp_path


def _verdict(audit_id: str, status: str = "SAFE") -> VerdictWithoutKey:
    return VerdictWithoutKey(
        address="bc1qx",
        status=status,  # type: ignore[arg-type]
        finding="none",
        confidence=0.9,
        key_fingerprint=None,
        recommendation="ok",
        evidence_refs=(),
        audit_id=audit_id,
        checks_performed=("test",),
    )


def test_db_path_creates_per_audit_dir(isolated_data_dir: Path) -> None:
    audit_id = "00000000-0000-0000-0000-000000000001"
    p = db_path(audit_id)
    assert audit_id in str(p)
    assert p.parent.exists()


def test_open_db_applies_schema(isolated_data_dir: Path) -> None:
    audit_id = "00000000-0000-0000-0000-000000000002"
    with open_db(audit_id) as conn:
        cur = conn.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
        tables = {row[0] for row in cur.fetchall()}
    assert {"audits", "transactions", "signatures", "address_pubkeys", "findings"} <= tables


def test_audit_lifecycle_round_trip(isolated_data_dir: Path) -> None:
    audit_id = "00000000-0000-0000-0000-000000000003"
    with open_db(audit_id) as conn:
        record_audit_start(
            conn,
            audit_id=audit_id,
            address="bc1qx",
            toolkit_version="1.0.0",
            ownership_proof_hash="deadbeef",
        )
        cur = conn.execute("SELECT status, finished_at FROM audits WHERE audit_id = ?", (audit_id,))
        status, finished = cur.fetchone()
        assert status == "running"
        assert finished is None

        record_audit_finish(conn, audit_id=audit_id, verdict=_verdict(audit_id, "SAFE"))
        cur = conn.execute("SELECT status, finished_at FROM audits WHERE audit_id = ?", (audit_id,))
        status, finished = cur.fetchone()
        assert status == "safe"
        assert finished is not None


def test_audit_finish_maps_status_correctly(isolated_data_dir: Path) -> None:
    audit_id = "00000000-0000-0000-0000-000000000004"
    with open_db(audit_id) as conn:
        record_audit_start(
            conn,
            audit_id=audit_id,
            address="bc1qx",
            toolkit_version="1.0.0",
            ownership_proof_hash="deadbeef",
        )
        record_audit_finish(conn, audit_id=audit_id, verdict=_verdict(audit_id, "VULNERABLE"))
        cur = conn.execute("SELECT status FROM audits WHERE audit_id = ?", (audit_id,))
        assert cur.fetchone()[0] == "vulnerable"


def test_insert_signatures_round_trip(isolated_data_dir: Path) -> None:
    audit_id = "00000000-0000-0000-0000-000000000005"
    rec = SignatureRecord(
        txid="aa" * 32,
        vin_index=0,
        pubkey_compressed=b"\x02" + b"\x05" * 32,
        r=0x1234567890,
        s=0xABCDEF01,
        z=0xDEADBEEF,
        sighash_type=1,
        script_type="p2wpkh",
    )
    with open_db(audit_id) as conn:
        n = insert_signatures(conn, [rec])
        assert n == 1
        cur = conn.execute("SELECT pubkey_hex, r, sighash_type, script_type FROM signatures")
        row = cur.fetchone()
        assert row[0] == rec.pubkey_compressed.hex()
        assert int.from_bytes(row[1], "big") == rec.r
        assert row[2] == 1
        assert row[3] == "p2wpkh"


def test_insert_signatures_idempotent(isolated_data_dir: Path) -> None:
    """Insert OR REPLACE — re-inserting same (txid, vin_index) keeps one row."""
    audit_id = "00000000-0000-0000-0000-000000000006"
    rec = SignatureRecord(
        txid="aa" * 32,
        vin_index=0,
        pubkey_compressed=b"\x02" + b"\x05" * 32,
        r=1,
        s=2,
        z=3,
        sighash_type=1,
        script_type="p2wpkh",
    )
    with open_db(audit_id) as conn:
        insert_signatures(conn, [rec, rec, rec])
        cur = conn.execute("SELECT COUNT(*) FROM signatures")
        assert cur.fetchone()[0] == 1


def test_findings_round_trip(isolated_data_dir: Path) -> None:
    audit_id = "00000000-0000-0000-0000-000000000007"
    with open_db(audit_id) as conn:
        record_audit_start(
            conn,
            audit_id=audit_id,
            address="bc1qx",
            toolkit_version="1.0.0",
            ownership_proof_hash="deadbeef",
        )
        record_finding(
            conn,
            audit_id=audit_id,
            severity="high",
            kind="r_collision",
            pubkey_hex="0205" * 17 + "ab",  # arbitrary
            payload={"r_prefix": "deadbe"},
        )
        record_finding(
            conn,
            audit_id=audit_id,
            severity="medium",
            kind="lattice_bias",
            pubkey_hex=None,
            payload={"hypothesis": "top_bits_zero", "bias_bits": 8},
        )
        findings = get_findings(conn, audit_id)
        assert len(findings) == 2
        assert findings[0]["kind"] == "r_collision"
        assert findings[1]["kind"] == "lattice_bias"
        assert findings[1]["pubkey_hex"] is None
        payload1 = findings[1]["payload"]
        assert isinstance(payload1, dict)
        assert payload1["hypothesis"] == "top_bits_zero"


def test_get_findings_empty(isolated_data_dir: Path) -> None:
    audit_id = "00000000-0000-0000-0000-000000000008"
    with open_db(audit_id) as conn:
        record_audit_start(
            conn,
            audit_id=audit_id,
            address="bc1qx",
            toolkit_version="1.0.0",
            ownership_proof_hash="deadbeef",
        )
        assert get_findings(conn, audit_id) == []


def test_open_db_idempotent(isolated_data_dir: Path) -> None:
    """Reopening an existing DB doesn't reapply schema or break."""
    audit_id = "00000000-0000-0000-0000-000000000009"
    with open_db(audit_id) as conn:
        record_audit_start(
            conn,
            audit_id=audit_id,
            address="bc1qx",
            toolkit_version="1.0.0",
            ownership_proof_hash="deadbeef",
        )
    with open_db(audit_id) as conn:
        cur = conn.execute("SELECT COUNT(*) FROM audits")
        assert cur.fetchone()[0] == 1
