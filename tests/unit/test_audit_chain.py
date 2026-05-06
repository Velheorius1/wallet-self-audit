"""Unit tests for the hash-chained audit log."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from wallet_self_audit.logging import audit_chain
from wallet_self_audit.logging.audit_chain import (
    ChainBreak,
    append_event,
    audit_chain_path,
    verify_chain,
)


@pytest.fixture
def isolated_chain(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    """Redirect the chain log to a tmp dir so tests never touch ~/.local."""
    target = tmp_path / "audit.jsonl"
    monkeypatch.setattr(audit_chain, "audit_chain_path", lambda: target)
    return target


def test_append_first_event_uses_genesis_prev(isolated_chain: Path) -> None:
    rec = append_event("audit_started", {"address": "bc1qx"})
    assert rec["seq"] == 0
    assert rec["prev_hash"] == "0" * 64
    assert isinstance(rec["hash"], str)
    assert len(rec["hash"]) == 64


def test_append_chains_to_previous(isolated_chain: Path) -> None:
    a = append_event("audit_started", {"address": "bc1qx"})
    b = append_event("vector_finished", {"vector": "milk_sad"})
    assert b["seq"] == 1
    assert b["prev_hash"] == a["hash"]


def test_verify_chain_clean_returns_empty(isolated_chain: Path) -> None:
    append_event("audit_started", {"address": "bc1qx"})
    append_event("vector_finished", {"vector": "milk_sad"})
    append_event("audit_finished", {"status": "SAFE"})
    assert verify_chain() == []


def test_verify_chain_detects_tampering(isolated_chain: Path) -> None:
    """Modify a payload after the fact → hash mismatch on that line."""
    append_event("audit_started", {"address": "bc1qx"})
    append_event("vector_finished", {"vector": "milk_sad"})
    append_event("audit_finished", {"status": "SAFE"})

    # Tamper: rewrite line 1 with a different vector name. The stored
    # hash won't match the new payload.
    lines = isolated_chain.read_text(encoding="utf-8").splitlines()
    rec = json.loads(lines[1])
    rec["vector"] = "tampered"
    lines[1] = json.dumps(rec, sort_keys=True, separators=(",", ":"))
    isolated_chain.write_text("\n".join(lines) + "\n", encoding="utf-8")

    breaks = verify_chain()
    assert len(breaks) == 1
    assert breaks[0].seq == 1
    assert "hash mismatch" in breaks[0].reason


def test_verify_chain_detects_out_of_order(isolated_chain: Path) -> None:
    """Reordering lines breaks the seq sequence."""
    append_event("a", {"x": 1})
    append_event("b", {"x": 2})
    append_event("c", {"x": 3})

    lines = isolated_chain.read_text(encoding="utf-8").splitlines()
    lines[0], lines[1] = lines[1], lines[0]
    isolated_chain.write_text("\n".join(lines) + "\n", encoding="utf-8")

    breaks = verify_chain()
    assert len(breaks) == 1
    assert "seq" in breaks[0].reason.lower()


def test_verify_empty_chain_returns_empty(isolated_chain: Path) -> None:
    """No file at all → no breaks (empty chain is trivially valid)."""
    assert verify_chain() == []


def test_chain_break_immutable() -> None:
    cb = ChainBreak(seq=0, reason="x")
    with pytest.raises(AttributeError):
        cb.seq = 99  # type: ignore[misc]


def test_audit_chain_path_under_state_dir(monkeypatch: pytest.MonkeyPatch) -> None:
    """The default path is ~/.local/state/wsa/audit.jsonl."""
    p = audit_chain_path()
    assert p.name == "audit.jsonl"
    assert ".local" in str(p) and "state" in str(p)
