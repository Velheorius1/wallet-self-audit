"""Sighash builder unit tests — canonical BIP-143 vectors."""

from __future__ import annotations

import pytest

from wallet_self_audit.crypto.sighash import (
    SIGHASH_ALL,
    SIGHASH_ANYONECANPAY,
    SIGHASH_NONE,
    SIGHASH_SINGLE,
    SighashUnsupported,
    Transaction,
    TxIn,
    TxOut,
    assert_supported_sighash,
    bip143_sighash_all_p2wpkh,
    legacy_sighash_all,
)


# ---------------------------------------------------------------------------
# BIP-143 canonical native P2WPKH vector (Vector 1 of the BIP-143 spec).
# ---------------------------------------------------------------------------
def _canonical_bip143_tx() -> Transaction:
    return Transaction(
        version=1,
        inputs=(
            TxIn(
                prev_txid=bytes.fromhex(
                    "9f96ade4b41d5433f4eda31e1738ec2b36f6e7d1420d94a6af99801a88f7f7ff"
                ),
                prev_vout=0,
                sequence=0xFFFFFFEE,
            ),
            TxIn(
                prev_txid=bytes.fromhex(
                    "8ac60eb9575db5b2d987e29f301b5b819ea83a5c6579d282d189cc04b8e151ef"
                ),
                prev_vout=1,
                sequence=0xFFFFFFFF,
            ),
        ),
        outputs=(
            TxOut(
                value=112340000,
                script_pubkey=bytes.fromhex("76a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac"),
            ),
            TxOut(
                value=223450000,
                script_pubkey=bytes.fromhex("76a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac"),
            ),
        ),
        locktime=0x11,
        has_witness=True,
    )


def test_bip143_canonical_vector_1() -> None:
    """Validate BIP-143 spec vector 1 byte-identically."""
    tx = _canonical_bip143_tx()
    z = bip143_sighash_all_p2wpkh(
        tx,
        input_index=1,
        prev_value=600000000,
        prev_pkh=bytes.fromhex("1d0f172a0ecb48aee1be1f2687d2963ae33f71a1"),
    )
    expected = 0xC37AF31116D1B27CAF68AAE9E3AC82F1477929014D5B917657D0EB49478CB670
    assert z == expected


def test_bip143_input_index_out_of_range() -> None:
    tx = _canonical_bip143_tx()
    with pytest.raises(IndexError):
        bip143_sighash_all_p2wpkh(
            tx,
            input_index=99,
            prev_value=1,
            prev_pkh=b"\x00" * 20,
        )


def test_bip143_pkh_must_be_20_bytes() -> None:
    tx = _canonical_bip143_tx()
    with pytest.raises(ValueError, match="must be 20 bytes"):
        bip143_sighash_all_p2wpkh(tx, input_index=1, prev_value=1, prev_pkh=b"\x00" * 19)


# ---------------------------------------------------------------------------
# Legacy SIGHASH_ALL — sanity test (vary tx, ensure z changes).
# ---------------------------------------------------------------------------
def test_legacy_sighash_changes_with_input_index() -> None:
    """Same tx, different input_index → different z (sanity)."""
    tx = Transaction(
        version=1,
        inputs=(
            TxIn(
                prev_txid=b"\x01" * 32,
                prev_vout=0,
                sequence=0xFFFFFFFF,
            ),
            TxIn(
                prev_txid=b"\x02" * 32,
                prev_vout=1,
                sequence=0xFFFFFFFF,
            ),
        ),
        outputs=(
            TxOut(
                value=10000,
                script_pubkey=b"\x76\xa9\x14" + b"\x03" * 20 + b"\x88\xac",
            ),
        ),
        locktime=0,
    )
    spk = b"\x76\xa9\x14" + b"\x05" * 20 + b"\x88\xac"
    z0 = legacy_sighash_all(tx, 0, spk)
    z1 = legacy_sighash_all(tx, 1, spk)
    assert z0 != z1
    # Both must be 256-bit ints.
    for z in (z0, z1):
        assert 0 < z < 1 << 256


def test_legacy_sighash_input_out_of_range() -> None:
    tx = Transaction(
        version=1,
        inputs=(TxIn(prev_txid=b"\x01" * 32, prev_vout=0, sequence=0xFFFFFFFF),),
        outputs=(),
        locktime=0,
    )
    with pytest.raises(IndexError):
        legacy_sighash_all(tx, 99, b"")


# ---------------------------------------------------------------------------
# Sighash-type acceptance gate.
# ---------------------------------------------------------------------------
def test_assert_supported_sighash_accepts_all() -> None:
    assert assert_supported_sighash(SIGHASH_ALL) is True


@pytest.mark.parametrize(
    "bad",
    [
        SIGHASH_NONE,
        SIGHASH_SINGLE,
        SIGHASH_ANYONECANPAY,
        SIGHASH_ALL | SIGHASH_ANYONECANPAY,
        SIGHASH_NONE | SIGHASH_ANYONECANPAY,
        SIGHASH_SINGLE | SIGHASH_ANYONECANPAY,
        0xFF,  # nonsense
    ],
)
def test_assert_supported_sighash_rejects_others(bad: int) -> None:
    with pytest.raises(SighashUnsupported):
        assert_supported_sighash(bad)
