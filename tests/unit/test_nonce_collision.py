"""Unit tests for ``nonce.collision`` — duplicate-r grouping."""

from __future__ import annotations

from wallet_self_audit.nonce.collision import find_collisions
from wallet_self_audit.nonce.extractor import SignatureRecord


def _rec(txid_byte: int, vin: int, pk: bytes, r: int, s: int, z: int) -> SignatureRecord:
    return SignatureRecord(
        txid=f"{txid_byte:02x}" * 32,
        vin_index=vin,
        pubkey_compressed=pk,
        r=r,
        s=s,
        z=z,
        sighash_type=1,
        script_type="p2wpkh",
    )


def test_no_collisions_returns_empty() -> None:
    pk = b"\x02" + b"\xab" * 32
    records = [
        _rec(0x01, 0, pk, r=10, s=100, z=1000),
        _rec(0x02, 0, pk, r=20, s=200, z=2000),
    ]
    assert find_collisions(records) == []


def test_real_collision_grouped() -> None:
    pk = b"\x02" + b"\xab" * 32
    records = [
        _rec(0x01, 0, pk, r=42, s=100, z=1000),
        _rec(0x02, 0, pk, r=42, s=200, z=2000),
    ]
    groups = find_collisions(records)
    assert len(groups) == 1
    assert groups[0].pubkey_compressed == pk
    assert groups[0].r == 42
    assert len(groups[0].records) == 2


def test_duplicate_signature_not_a_collision() -> None:
    """Same (z, s) for the same r is just the same sig — exclude."""
    pk = b"\x02" + b"\xab" * 32
    records = [
        _rec(0x01, 0, pk, r=42, s=100, z=1000),
        _rec(0x02, 0, pk, r=42, s=100, z=1000),
    ]
    assert find_collisions(records) == []


def test_collisions_are_per_pubkey() -> None:
    """Two different pubkeys with the same r are unrelated."""
    pk_a = b"\x02" + b"\xaa" * 32
    pk_b = b"\x02" + b"\xbb" * 32
    records = [
        _rec(0x01, 0, pk_a, r=42, s=100, z=1000),
        _rec(0x02, 0, pk_b, r=42, s=200, z=2000),
    ]
    assert find_collisions(records) == []


def test_three_signatures_same_r_grouped_once() -> None:
    pk = b"\x02" + b"\xab" * 32
    records = [
        _rec(0x01, 0, pk, r=42, s=100, z=1000),
        _rec(0x02, 0, pk, r=42, s=200, z=2000),
        _rec(0x03, 0, pk, r=42, s=300, z=3000),
    ]
    groups = find_collisions(records)
    assert len(groups) == 1
    assert len(groups[0].records) == 3
