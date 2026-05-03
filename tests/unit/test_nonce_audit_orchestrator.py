"""Unit tests for ``vectors.nonce_audit`` — orchestrator paths."""

from __future__ import annotations

import hashlib
from typing import Any

import pytest
from coincurve import PrivateKey

from wallet_self_audit.nonce.extractor import SignatureRecord
from wallet_self_audit.vectors import nonce_audit as nonce_audit_module
from wallet_self_audit.vectors.nonce_audit import (
    NonceAuditConfig,
    run_nonce_audit,
    run_nonce_audit_informational,
)

_SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


class _StubClient:
    """Trivial stub — the orchestrator patches the extractor directly so we
    never reach the client. We pass it just to satisfy the Protocol."""

    def get_address_txs(self, address: str) -> list[dict[str, object]]:
        return []

    def get_tx(self, txid: str) -> dict[str, object]:
        return {}

    def get_raw_tx_hex(self, txid: str) -> str:
        return ""


def _sign(z: int, d: int, k: int) -> tuple[int, int]:
    pub = PrivateKey(k.to_bytes(32, "big")).public_key.format(compressed=False)
    rx = int.from_bytes(pub[1:33], "big")
    r = rx % _SECP256K1_N
    s = (pow(k, -1, _SECP256K1_N) * (z + r * d)) % _SECP256K1_N
    return r, s


def _vulnerable_records(d: int, k: int) -> list[SignatureRecord]:
    z_a = int.from_bytes(hashlib.sha256(b"msg a").digest(), "big") % _SECP256K1_N
    z_b = int.from_bytes(hashlib.sha256(b"msg b").digest(), "big") % _SECP256K1_N
    r_a, s_a = _sign(z_a, d, k)
    r_b, s_b = _sign(z_b, d, k)
    Q = PrivateKey(d.to_bytes(32, "big")).public_key.format(compressed=True)
    return [
        SignatureRecord(
            txid="a" * 64,
            vin_index=0,
            pubkey_compressed=Q,
            r=r_a,
            s=s_a,
            z=z_a,
            sighash_type=1,
            script_type="p2wpkh",
        ),
        SignatureRecord(
            txid="b" * 64,
            vin_index=0,
            pubkey_compressed=Q,
            r=r_b,
            s=s_b,
            z=z_b,
            sighash_type=1,
            script_type="p2wpkh",
        ),
    ]


def _clean_records(d: int) -> list[SignatureRecord]:
    """Two outgoing signatures with DIFFERENT k values → no collision."""
    Q = PrivateKey(d.to_bytes(32, "big")).public_key.format(compressed=True)
    out: list[SignatureRecord] = []
    for i, msg in enumerate([b"msg one", b"msg two"]):
        z = int.from_bytes(hashlib.sha256(msg).digest(), "big") % _SECP256K1_N
        k_unique = (
            int.from_bytes(hashlib.sha256(b"k-" + msg).digest(), "big") % (_SECP256K1_N - 1) + 1
        )
        r, s = _sign(z, d, k_unique)
        out.append(
            SignatureRecord(
                txid=f"{i:02x}" * 32,
                vin_index=0,
                pubkey_compressed=Q,
                r=r,
                s=s,
                z=z,
                sighash_type=1,
                script_type="p2wpkh",
            )
        )
    return out


def test_orchestrator_detects_synthetic_collision(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    d = 0x1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF
    k = 0xFEDCBA0987654321FEDCBA0987654321FEDCBA0987654321FEDCBA0987654321
    records = _vulnerable_records(d, k)

    def stub(addr: str, client: Any, *, max_txs: int = 200) -> list[SignatureRecord]:
        return records

    monkeypatch.setattr(nonce_audit_module, "extract_outgoing_signatures", stub)

    cfg = NonceAuditConfig(address="bc1qexample")
    verdict = run_nonce_audit(cfg, _StubClient())
    assert verdict.status == "VULNERABLE"
    assert verdict.finding == "r_collision"
    assert verdict.key_fingerprint is not None
    assert len(verdict.evidence_refs) == 2


def test_orchestrator_clean_wallet_returns_safe(monkeypatch: pytest.MonkeyPatch) -> None:
    d = 0xDEADBEEF12345678DEADBEEF12345678DEADBEEF12345678DEADBEEF12345678
    records = _clean_records(d)

    def stub(addr: str, client: Any, *, max_txs: int = 200) -> list[SignatureRecord]:
        return records

    monkeypatch.setattr(nonce_audit_module, "extract_outgoing_signatures", stub)

    cfg = NonceAuditConfig(address="bc1qclean")
    verdict = run_nonce_audit(cfg, _StubClient())
    assert verdict.status == "SAFE"
    assert verdict.finding == "none"
    assert verdict.key_fingerprint is None


def test_orchestrator_empty_wallet_returns_suspicious(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def stub(addr: str, client: Any, *, max_txs: int = 200) -> list[SignatureRecord]:
        return []

    monkeypatch.setattr(nonce_audit_module, "extract_outgoing_signatures", stub)

    cfg = NonceAuditConfig(address="bc1qempty")
    verdict = run_nonce_audit(cfg, _StubClient())
    assert verdict.status == "SUSPICIOUS"
    assert verdict.finding == "none"


def test_informational_mode_returns_counts(monkeypatch: pytest.MonkeyPatch) -> None:
    d = 0x1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF
    k = 0xFEDCBA0987654321FEDCBA0987654321FEDCBA0987654321FEDCBA0987654321
    records = _vulnerable_records(d, k)

    def stub(addr: str, client: Any, *, max_txs: int = 200) -> list[SignatureRecord]:
        return records

    monkeypatch.setattr(nonce_audit_module, "extract_outgoing_signatures", stub)

    info = run_nonce_audit_informational(NonceAuditConfig(address="bc1q"), _StubClient())
    assert info["address"] == "bc1q"
    assert info["outgoing_tx_count"] == 2
    assert info["collision_groups"] == 1
    assert info["informational_only"] is True
