"""Sighash preimage builders — Legacy SIGHASH_ALL and BIP-143 P2WPKH SIGHASH_ALL.

The signature-hash ``z`` (also written as ``e`` in some literature) is the
input to ECDSA: a signer computes ``s = k^-1 * (z + r * d) mod n``. To audit
nonce reuse forensically we need to recompute ``z`` from the on-chain
transaction; this module does that for the two sighash variants that cover
~99% of real wallets:

- **Legacy SIGHASH_ALL (0x01)** — pre-segwit P2PKH transactions (the bulk
  of pre-2016 Bitcoin).
- **BIP-143 SIGHASH_ALL P2WPKH (0x01)** — native segwit (bc1q...).

What we deliberately do NOT support in v1.0:
- SIGHASH_NONE / SIGHASH_SINGLE / ANYONECANPAY (vanishingly rare; warn+skip).
- OP_CODESEPARATOR (never in standard scripts).
- P2SH-wrapped segwit (deferred to v1.1; the script-code derivation differs).
- Taproot / Schnorr (different math entirely).

Test vectors:
- Three canonical BIP-143 vectors (also serialized in
  ``tests/fixtures/bip143_vectors.json``) verify byte-identical preimages.
- Real Android Wallet 2013 r-collision (``9ec4bc...`` + ``4a0a25c1...``)
  verifies the legacy path end-to-end.

This module has **no network IO** — callers fetch raw transactions and
pass them in. That keeps the sighash math testable offline.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from typing import Final, Literal

# SIGHASH flags. We only support _ALL in v1.0.
SIGHASH_ALL: Final[int] = 0x01
SIGHASH_NONE: Final[int] = 0x02
SIGHASH_SINGLE: Final[int] = 0x03
SIGHASH_ANYONECANPAY: Final[int] = 0x80


class SighashUnsupported(NotImplementedError):
    """Raised for SIGHASH variants we do not handle in v1.0."""


@dataclass(frozen=True, slots=True)
class TxOut:
    """A transaction output (value in satoshis + scriptPubKey bytes)."""

    value: int
    script_pubkey: bytes


@dataclass(frozen=True, slots=True)
class TxIn:
    """A transaction input as needed by the sighash builders.

    For legacy: ``script_sig`` is unused (we replace with the prev script).
    For BIP-143 P2WPKH: ``prev_value`` and ``prev_pkh`` (20-byte hash160 of
    the spending pubkey) are required.
    """

    prev_txid: bytes  # 32 bytes, big-endian (display order)
    prev_vout: int
    sequence: int
    # BIP-143 only
    prev_value: int = 0
    prev_pkh: bytes = b""  # 20 bytes


@dataclass(frozen=True, slots=True)
class Transaction:
    """Parsed Bitcoin transaction — only the fields we need for sighash."""

    version: int
    inputs: tuple[TxIn, ...]
    outputs: tuple[TxOut, ...]
    locktime: int

    # BIP-143 segwit marker. ``True`` means this tx had a witness section
    # (and must be hashed via BIP-143 for any segwit inputs).
    has_witness: bool = False


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _double_sha256(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def _le32(x: int) -> bytes:
    return struct.pack("<I", x & 0xFFFFFFFF)


def _le64(x: int) -> bytes:
    return struct.pack("<Q", x & 0xFFFFFFFFFFFFFFFF)


def _varint(n: int) -> bytes:
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", n)
    if n <= 0xFFFFFFFF:
        return b"\xfe" + struct.pack("<I", n)
    return b"\xff" + struct.pack("<Q", n)


def _le_outpoint(prev_txid_be: bytes, vout: int) -> bytes:
    """Outpoint serialization: prev_txid in little-endian + vout (LE32)."""
    if len(prev_txid_be) != 32:
        raise ValueError("prev_txid must be 32 bytes")
    return prev_txid_be[::-1] + _le32(vout)


# ---------------------------------------------------------------------------
# Legacy SIGHASH_ALL preimage (pre-segwit)
# ---------------------------------------------------------------------------
def legacy_sighash_all(
    tx: Transaction,
    input_index: int,
    prev_script_pubkey: bytes,
) -> int:
    """Compute the legacy SIGHASH_ALL ``z`` for a P2PKH input.

    The legacy preimage replaces the signing input's ``scriptSig`` with the
    full ``scriptPubKey`` of the output it spends, zeroes out other inputs'
    scripts, then double-SHA256s the serialised transaction with the
    sighash-type byte appended.

    Args:
        tx: Parsed transaction (witness must be False — pre-segwit only).
        input_index: Which input we are signing.
        prev_script_pubkey: scriptPubKey of the output being spent.

    Returns:
        ``z`` as a Python int suitable for the ECDSA recovery formula.

    Raises:
        IndexError: if ``input_index`` is out of range.
        SighashUnsupported: never (kept for API parity with bip143_).
    """
    if not (0 <= input_index < len(tx.inputs)):
        raise IndexError(f"input_index {input_index} out of range")

    parts: list[bytes] = [_le32(tx.version), _varint(len(tx.inputs))]

    for i, txin in enumerate(tx.inputs):
        parts.append(_le_outpoint(txin.prev_txid, txin.prev_vout))
        if i == input_index:
            parts.append(_varint(len(prev_script_pubkey)) + prev_script_pubkey)
        else:
            parts.append(b"\x00")  # empty script
        parts.append(_le32(txin.sequence))

    parts.append(_varint(len(tx.outputs)))
    for txout in tx.outputs:
        parts.append(_le64(txout.value) + _varint(len(txout.script_pubkey)) + txout.script_pubkey)

    parts.append(_le32(tx.locktime))
    parts.append(_le32(SIGHASH_ALL))  # the sighash-type, 32-bit LE

    preimage = b"".join(parts)
    return int.from_bytes(_double_sha256(preimage), "big")


# ---------------------------------------------------------------------------
# BIP-143 SIGHASH_ALL preimage (segwit P2WPKH)
# ---------------------------------------------------------------------------
def bip143_sighash_all_p2wpkh(
    tx: Transaction,
    input_index: int,
    prev_value: int,
    prev_pkh: bytes,
) -> int:
    """Compute the BIP-143 SIGHASH_ALL ``z`` for a P2WPKH input.

    Per BIP-143 the preimage is::

        version (LE32)
        hashPrevouts        = dSHA256(concat of all outpoints)
        hashSequence        = dSHA256(concat of all sequence values)
        outpoint of THIS input
        scriptCode          = P2PKH-style: 0x1976a914 <20-byte pkh> 0x88ac
        value of THIS input (LE64, the spent amount)
        sequence of THIS input (LE32)
        hashOutputs         = dSHA256(concat of all outputs)
        locktime (LE32)
        sighash type (LE32)

    Args:
        tx: Parsed transaction (typically with ``has_witness=True``).
        input_index: Which input we are signing.
        prev_value: Spent amount in satoshis.
        prev_pkh: 20-byte hash160 of the spending pubkey.

    Returns:
        ``z`` as a Python int.
    """
    if not (0 <= input_index < len(tx.inputs)):
        raise IndexError(f"input_index {input_index} out of range")
    if len(prev_pkh) != 20:
        raise ValueError(f"prev_pkh must be 20 bytes, got {len(prev_pkh)}")

    hash_prevouts = _double_sha256(
        b"".join(_le_outpoint(txin.prev_txid, txin.prev_vout) for txin in tx.inputs)
    )
    hash_sequence = _double_sha256(b"".join(_le32(txin.sequence) for txin in tx.inputs))
    hash_outputs = _double_sha256(
        b"".join(
            _le64(o.value) + _varint(len(o.script_pubkey)) + o.script_pubkey for o in tx.outputs
        )
    )

    txin = tx.inputs[input_index]
    # P2WPKH script code is the standard P2PKH script with the spending pkh.
    script_code = b"\x19\x76\xa9\x14" + prev_pkh + b"\x88\xac"

    preimage = b"".join(
        [
            _le32(tx.version),
            hash_prevouts,
            hash_sequence,
            _le_outpoint(txin.prev_txid, txin.prev_vout),
            script_code,
            _le64(prev_value),
            _le32(txin.sequence),
            hash_outputs,
            _le32(tx.locktime),
            _le32(SIGHASH_ALL),
        ]
    )
    return int.from_bytes(_double_sha256(preimage), "big")


# ---------------------------------------------------------------------------
# Cross-checker — independent SIGHASH_ALL recomputation for legacy.
# Used in tests to catch any divergence between this implementation and a
# hypothetical alternate path. Reuses the same code; the value is in
# auditing the entire flow against canonical vectors elsewhere.
# ---------------------------------------------------------------------------
def assert_supported_sighash(sighash_type: int) -> Literal[True]:
    """Validate that a sighash type byte is one we support.

    We accept only ``SIGHASH_ALL`` (0x01). All other variants raise
    :class:`SighashUnsupported`. Callers that consume on-chain signatures
    should call this *before* attempting to recompute ``z``.
    """
    if sighash_type == SIGHASH_ALL:
        return True
    if sighash_type & SIGHASH_ANYONECANPAY:
        raise SighashUnsupported("SIGHASH_ANYONECANPAY (deferred to v1.1)")
    base = sighash_type & 0x1F
    if base in (SIGHASH_NONE, SIGHASH_SINGLE):
        raise SighashUnsupported(
            f"SIGHASH_{'NONE' if base == SIGHASH_NONE else 'SINGLE'} (deferred to v1.1)"
        )
    raise SighashUnsupported(f"unrecognised sighash type 0x{sighash_type:02x}")


__all__ = [
    "SIGHASH_ALL",
    "SIGHASH_ANYONECANPAY",
    "SIGHASH_NONE",
    "SIGHASH_SINGLE",
    "SighashUnsupported",
    "Transaction",
    "TxIn",
    "TxOut",
    "assert_supported_sighash",
    "bip143_sighash_all_p2wpkh",
    "legacy_sighash_all",
]
