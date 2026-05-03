"""Unit tests for the raw-transaction parser inside ``nonce.extractor``.

We synthesize legacy and segwit serialised transactions, run them through
``_parse_raw_tx``, and check the resulting ``Transaction`` matches what we
encoded. We also test the per-input scriptSig / witness parsers and the
sighash split.
"""

from __future__ import annotations

import hashlib
import struct

import pytest

from wallet_self_audit.crypto.sighash import SIGHASH_ALL
from wallet_self_audit.nonce import extractor as ext
from wallet_self_audit.nonce.extractor import (
    SignatureRecord,
    _parse_p2pkh_input,
    _parse_p2wpkh_witness,
    _parse_raw_tx,
    _split_sig_and_sighash,
    extract_outgoing_signatures,
    signature_records_from_iter,
)


# ---------------------------------------------------------------------------
# Helpers — build serialised transactions byte-for-byte.
# ---------------------------------------------------------------------------
def _varint(n: int) -> bytes:
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", n)
    if n <= 0xFFFFFFFF:
        return b"\xfe" + struct.pack("<I", n)
    return b"\xff" + struct.pack("<Q", n)


def _build_legacy_tx(
    *,
    version: int,
    prev_txid_be: bytes,
    prev_vout: int,
    scriptsig: bytes,
    sequence: int,
    out_value: int,
    out_script: bytes,
    locktime: int,
) -> str:
    parts = [
        struct.pack("<I", version),
        _varint(1),
        prev_txid_be[::-1],
        struct.pack("<I", prev_vout),
        _varint(len(scriptsig)),
        scriptsig,
        struct.pack("<I", sequence),
        _varint(1),
        struct.pack("<Q", out_value),
        _varint(len(out_script)),
        out_script,
        struct.pack("<I", locktime),
    ]
    return b"".join(parts).hex()


def _build_segwit_tx(
    *,
    version: int,
    prev_txid_be: bytes,
    prev_vout: int,
    sequence: int,
    out_value: int,
    out_script: bytes,
    witness_stack: list[bytes],
    locktime: int,
) -> str:
    parts = [
        struct.pack("<I", version),
        b"\x00\x01",  # segwit marker + flag
        _varint(1),
        prev_txid_be[::-1],
        struct.pack("<I", prev_vout),
        _varint(0),  # empty scriptSig for native segwit
        struct.pack("<I", sequence),
        _varint(1),
        struct.pack("<Q", out_value),
        _varint(len(out_script)),
        out_script,
        _varint(len(witness_stack)),
    ]
    for w in witness_stack:
        parts.append(_varint(len(w)) + w)
    parts.append(struct.pack("<I", locktime))
    return b"".join(parts).hex()


# ---------------------------------------------------------------------------
# Parser tests
# ---------------------------------------------------------------------------
def test_parse_legacy_tx_roundtrip() -> None:
    raw = _build_legacy_tx(
        version=1,
        prev_txid_be=b"\xab" * 32,
        prev_vout=3,
        scriptsig=b"\x47" + b"\x01" * 71 + b"\x21" + b"\x02" * 33,
        sequence=0xFFFFFFFE,
        out_value=12345,
        out_script=b"\x76\xa9\x14" + b"\x05" * 20 + b"\x88\xac",
        locktime=42,
    )
    tx = _parse_raw_tx(raw)
    assert tx.version == 1
    assert len(tx.inputs) == 1
    assert tx.inputs[0].prev_txid == b"\xab" * 32
    assert tx.inputs[0].prev_vout == 3
    assert tx.inputs[0].sequence == 0xFFFFFFFE
    assert len(tx.outputs) == 1
    assert tx.outputs[0].value == 12345
    assert tx.locktime == 42
    assert tx.has_witness is False


def test_parse_segwit_tx_roundtrip() -> None:
    sig_with_type = b"\x30\x44" + b"\x42" * 68 + bytes([SIGHASH_ALL])
    pubkey = b"\x02" + b"\x03" * 32
    raw = _build_segwit_tx(
        version=2,
        prev_txid_be=b"\xcd" * 32,
        prev_vout=0,
        sequence=0xFFFFFFFF,
        out_value=98765,
        out_script=b"\x00\x14" + b"\x07" * 20,
        witness_stack=[sig_with_type, pubkey],
        locktime=0,
    )
    tx = _parse_raw_tx(raw)
    assert tx.version == 2
    assert tx.has_witness is True
    assert len(tx.inputs) == 1
    assert tx.outputs[0].value == 98765


# ---------------------------------------------------------------------------
# Per-input parsers
# ---------------------------------------------------------------------------
def test_parse_p2pkh_input_canonical() -> None:
    sig = b"\x47" + b"\x01" * 71  # 71-byte sig + sighash byte ≈ 72; we'll skip
    sig_bytes = b"\x01" * 72
    pubkey = b"\x02" + b"\x03" * 32
    scriptsig = bytes([len(sig_bytes)]) + sig_bytes + bytes([len(pubkey)]) + pubkey
    parsed = _parse_p2pkh_input(scriptsig)
    assert parsed is not None
    assert parsed[0] == sig_bytes
    assert parsed[1] == pubkey
    _ = sig  # unused (kept to document the canonical layout)


def test_parse_p2pkh_input_empty_returns_none() -> None:
    assert _parse_p2pkh_input(b"") is None


def test_parse_p2pkh_input_truncated() -> None:
    # length byte says 100 but only 5 bytes follow.
    assert _parse_p2pkh_input(b"\x64\x01\x02\x03\x04\x05") is None


def test_parse_p2pkh_input_bad_pubkey_length() -> None:
    sig_bytes = b"\x01" * 72
    pubkey = b"\x02" + b"\x03" * 10  # only 11 bytes — not 33 or 65
    scriptsig = bytes([len(sig_bytes)]) + sig_bytes + bytes([len(pubkey)]) + pubkey
    assert _parse_p2pkh_input(scriptsig) is None


def test_parse_p2wpkh_witness_canonical() -> None:
    sig = b"\x42" * 72
    pubkey = b"\x02" + b"\x05" * 32
    parsed = _parse_p2wpkh_witness((sig, pubkey))
    assert parsed == (sig, pubkey)


def test_parse_p2wpkh_witness_wrong_stack_size() -> None:
    pubkey = b"\x02" + b"\x05" * 32
    assert _parse_p2wpkh_witness((pubkey,)) is None
    assert _parse_p2wpkh_witness((pubkey, pubkey, pubkey)) is None


def test_parse_p2wpkh_witness_uncompressed_pubkey_rejected() -> None:
    sig = b"\x42" * 72
    pubkey = b"\x04" + b"\x05" * 64  # 65-byte uncompressed
    assert _parse_p2wpkh_witness((sig, pubkey)) is None


# ---------------------------------------------------------------------------
# split_sig_and_sighash
# ---------------------------------------------------------------------------
def test_split_sig_and_sighash_normal() -> None:
    assert _split_sig_and_sighash(b"\x30\x44" + b"\x01" * 70 + b"\x01") == (
        b"\x30\x44" + b"\x01" * 70,
        1,
    )


def test_split_sig_and_sighash_too_short_returns_none() -> None:
    assert _split_sig_and_sighash(b"\x01") is None
    assert _split_sig_and_sighash(b"") is None


# ---------------------------------------------------------------------------
# extract_outgoing_signatures — end-to-end with a stub client.
# ---------------------------------------------------------------------------
class _StubClient:
    def __init__(self, summaries: list[dict[str, object]], raw_hex: dict[str, str]) -> None:
        self._summaries = summaries
        self._raw_hex = raw_hex

    def get_address_txs(self, address: str) -> list[dict[str, object]]:
        return self._summaries

    def get_tx(self, txid: str) -> dict[str, object]:
        return {}

    def get_raw_tx_hex(self, txid: str) -> str:
        return self._raw_hex[txid]


def _build_signed_p2wpkh_tx(
    pubkey: bytes,
    sig_with_type: bytes,
    prev_txid_be: bytes = b"\xee" * 32,
) -> tuple[str, str]:
    """Return (raw_hex, txid_hex) for a 1-in 1-out P2WPKH signed tx."""
    raw = _build_segwit_tx(
        version=2,
        prev_txid_be=prev_txid_be,
        prev_vout=0,
        sequence=0xFFFFFFFF,
        out_value=10000,
        out_script=b"\x00\x14" + b"\x07" * 20,
        witness_stack=[sig_with_type, pubkey],
        locktime=0,
    )
    # txid = double-SHA256(serialise without witness data), in display order.
    # For a stub test we just use a deterministic hash of the raw hex — the
    # extractor only uses txid as a key.
    txid = hashlib.sha256(bytes.fromhex(raw)).hexdigest()
    return raw, txid


def test_extract_outgoing_signatures_skips_unsupported_sighash() -> None:
    """A signature with sighash != ALL must be skipped with a warning."""
    sig_der = b"\x30\x44" + b"\x01" * 70
    sig_with_type = sig_der + bytes([2])  # SIGHASH_NONE
    pubkey = b"\x02" + b"\x03" * 32
    raw, txid = _build_signed_p2wpkh_tx(pubkey, sig_with_type)

    summaries = [
        {
            "txid": txid,
            "vin": [
                {
                    "prevout": {
                        "scriptpubkey_address": "bc1qexample",
                        "scriptpubkey_type": "v0_p2wpkh",
                        "value": 50000,
                        "scriptpubkey": "00140707070707070707070707070707070707070707",
                    }
                }
            ],
        }
    ]
    client = _StubClient(summaries=summaries, raw_hex={txid: raw})
    out = extract_outgoing_signatures("bc1qexample", client)
    assert out == []


def test_extract_outgoing_signatures_skips_unsupported_script_type() -> None:
    """Inputs spending p2tr / p2sh are skipped (v1.0 limitation)."""
    sig_with_type = b"\x30\x44" + b"\x01" * 70 + b"\x01"
    pubkey = b"\x02" + b"\x03" * 32
    raw, txid = _build_signed_p2wpkh_tx(pubkey, sig_with_type)

    summaries = [
        {
            "txid": txid,
            "vin": [
                {
                    "prevout": {
                        "scriptpubkey_address": "bc1pexample",
                        "scriptpubkey_type": "v1_p2tr",
                        "value": 50000,
                        "scriptpubkey": "5120" + "07" * 32,
                    }
                }
            ],
        }
    ]
    client = _StubClient(summaries=summaries, raw_hex={txid: raw})
    out = extract_outgoing_signatures("bc1pexample", client)
    assert out == []


def test_extract_outgoing_signatures_skips_other_addresses() -> None:
    """Inputs that spend a different address must not appear in output."""
    sig_with_type = b"\x30\x44" + b"\x01" * 70 + b"\x01"
    pubkey = b"\x02" + b"\x03" * 32
    raw, txid = _build_signed_p2wpkh_tx(pubkey, sig_with_type)

    summaries = [
        {
            "txid": txid,
            "vin": [
                {
                    "prevout": {
                        "scriptpubkey_address": "bc1qsomeoneelse",
                        "scriptpubkey_type": "v0_p2wpkh",
                        "value": 50000,
                        "scriptpubkey": "00140707070707070707070707070707070707070707",
                    }
                }
            ],
        }
    ]
    client = _StubClient(summaries=summaries, raw_hex={txid: raw})
    out = extract_outgoing_signatures("bc1qexample", client)
    assert out == []


def test_extract_outgoing_signatures_empty_history() -> None:
    client = _StubClient(summaries=[], raw_hex={})
    assert extract_outgoing_signatures("bc1qexample", client) == []


def test_signature_records_from_iter() -> None:
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
    assert signature_records_from_iter(iter([rec])) == [rec]


# ---------------------------------------------------------------------------
# Smoke: HttpMempoolClient construction (cannot make real HTTP in CI).
# ---------------------------------------------------------------------------
def test_http_mempool_client_constructs() -> None:
    from wallet_self_audit.nonce.extractor import HttpMempoolClient

    c = HttpMempoolClient()
    try:
        # The base URL is normalised (trailing slash trimmed).
        assert c._base_url.startswith("https://")
    finally:
        c.close()


def test_extract_outgoing_signatures_handles_malformed_summary() -> None:
    """A summary without txid is silently skipped."""
    client = _StubClient(summaries=[{"not_a_txid": "x"}], raw_hex={})
    assert extract_outgoing_signatures("bc1qexample", client) == []


def test_extract_outgoing_signatures_handles_fetch_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If the raw-hex fetch raises, the tx is skipped — not the whole audit."""

    class BadClient:
        def get_address_txs(self, address: str) -> list[dict[str, object]]:
            return [{"txid": "ab" * 32, "vin": []}]

        def get_tx(self, txid: str) -> dict[str, object]:
            return {}

        def get_raw_tx_hex(self, txid: str) -> str:
            raise RuntimeError("boom")

    out = extract_outgoing_signatures("bc1qx", BadClient())
    assert out == []
    _ = ext  # imported for module-level access in case of future tests
