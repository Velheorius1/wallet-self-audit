"""Fetch and parse outgoing-transaction signatures from mempool.space.

Stage-A of the nonce audit: collect the ``(r, s, pubkey, z)`` tuples for
every signature input that *spends* the user's address. Stage-B (collision
detection) consumes these tuples directly.

The extractor is the only module in this package that touches the network,
and it only ever calls a public mempool.space-compatible API. Mnemonics
and entropy never reach this module.

API contract
------------
- ``MempoolClient`` is the wire-level adapter (HTTPS GET only).
- ``extract_outgoing_signatures(address, client)`` is the high-level
  entrypoint that returns parsed ``SignatureRecord``s.

Limitations in v1.0
-------------------
- Only spends from P2PKH (legacy) and P2WPKH (native segwit) inputs.
- P2SH-wrapped segwit, P2TR (Taproot) and multisig are skipped with a
  per-input warning.
- Sighash is SIGHASH_ALL only — anything else is skipped (extremely rare
  in practice; documented in ``docs/threat-model.md``).
"""

from __future__ import annotations

import logging
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Final, Protocol

import httpx

from wallet_self_audit.crypto.der import DERParseError, parse_der
from wallet_self_audit.crypto.sighash import (
    SIGHASH_ALL,
    Transaction,
    TxIn,
    TxOut,
    bip143_sighash_all_p2wpkh,
    legacy_sighash_all,
)

log = logging.getLogger(__name__)

_USER_AGENT: Final[str] = "wallet-self-audit/1.0"
_DEFAULT_TIMEOUT: Final[float] = 30.0


@dataclass(frozen=True, slots=True)
class SignatureRecord:
    """One parsed signature input. All fields are public chain data."""

    txid: str  # 64-hex
    vin_index: int
    pubkey_compressed: bytes  # 33 bytes
    r: int
    s: int
    z: int
    sighash_type: int
    script_type: str  # "p2pkh" | "p2wpkh"


class MempoolClient(Protocol):
    """Subset of mempool.space REST API we need.

    The Protocol lets tests inject a stub without inheriting.
    """

    def get_address_txs(self, address: str) -> list[dict[str, object]]: ...
    def get_tx(self, txid: str) -> dict[str, object]: ...
    def get_raw_tx_hex(self, txid: str) -> str: ...


class HttpMempoolClient:
    """Real mempool.space client over HTTPS."""

    def __init__(
        self,
        base_url: str = "https://mempool.space/api",
        timeout: float = _DEFAULT_TIMEOUT,
        client: httpx.Client | None = None,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._client = client or httpx.Client(timeout=timeout, headers={"User-Agent": _USER_AGENT})

    def get_address_txs(self, address: str) -> list[dict[str, object]]:
        """Return the address' transaction history (most recent first)."""
        r = self._client.get(f"{self._base_url}/address/{address}/txs")
        r.raise_for_status()
        data: object = r.json()
        if not isinstance(data, list):
            raise TypeError(f"unexpected response: {type(data).__name__}")
        out: list[dict[str, object]] = []
        for item in data:  # pyright: ignore[reportUnknownVariableType]
            if isinstance(item, dict):
                out.append(item)  # pyright: ignore[reportUnknownArgumentType]
        return out

    def get_tx(self, txid: str) -> dict[str, object]:
        r = self._client.get(f"{self._base_url}/tx/{txid}")
        r.raise_for_status()
        data: object = r.json()
        if not isinstance(data, dict):
            raise TypeError(f"unexpected response: {type(data).__name__}")
        return data  # pyright: ignore[reportUnknownVariableType]

    def get_raw_tx_hex(self, txid: str) -> str:
        r = self._client.get(f"{self._base_url}/tx/{txid}/hex")
        r.raise_for_status()
        return r.text.strip()

    def close(self) -> None:
        self._client.close()


# ---------------------------------------------------------------------------
# Raw transaction parsing (only the fields needed for sighash)
# ---------------------------------------------------------------------------
class _RawTxReader:
    """Tiny streaming parser for serialised transaction bytes."""

    __slots__ = ("data", "pos")

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.pos = 0

    def take(self, n: int) -> bytes:
        if self.pos + n > len(self.data):
            raise ValueError(f"unexpected end of tx (need {n}, pos={self.pos})")
        b = self.data[self.pos : self.pos + n]
        self.pos += n
        return b

    def varint(self) -> int:
        prefix = self.take(1)[0]
        if prefix < 0xFD:
            return prefix
        if prefix == 0xFD:
            return int.from_bytes(self.take(2), "little")
        if prefix == 0xFE:
            return int.from_bytes(self.take(4), "little")
        return int.from_bytes(self.take(8), "little")

    def remaining(self) -> int:
        return len(self.data) - self.pos


def _parse_raw_tx(raw_hex: str) -> Transaction:
    """Parse a serialised tx (BIP-141 segwit-aware) into a Transaction.

    Note: we do NOT keep witness data in the returned ``Transaction`` —
    callers parse witness bytes separately when constructing the BIP-143
    sighash. The ``has_witness`` flag is set when the segwit marker is seen.
    """
    rdr = _RawTxReader(bytes.fromhex(raw_hex))
    version = int.from_bytes(rdr.take(4), "little")
    has_witness = False

    # BIP-141 segwit marker: 0x00 0x01 immediately after version.
    if rdr.data[rdr.pos] == 0x00 and rdr.data[rdr.pos + 1] == 0x01:
        rdr.take(2)
        has_witness = True

    n_in = rdr.varint()
    inputs: list[TxIn] = []
    input_scriptsigs: list[bytes] = []
    for _ in range(n_in):
        prev_txid_le = rdr.take(32)
        prev_txid_be = prev_txid_le[::-1]
        prev_vout = int.from_bytes(rdr.take(4), "little")
        ssig_len = rdr.varint()
        scriptsig = rdr.take(ssig_len)
        sequence = int.from_bytes(rdr.take(4), "little")
        inputs.append(
            TxIn(
                prev_txid=prev_txid_be,
                prev_vout=prev_vout,
                sequence=sequence,
            )
        )
        input_scriptsigs.append(scriptsig)

    n_out = rdr.varint()
    outputs: list[TxOut] = []
    for _ in range(n_out):
        value = int.from_bytes(rdr.take(8), "little")
        spk_len = rdr.varint()
        spk = rdr.take(spk_len)
        outputs.append(TxOut(value=value, script_pubkey=spk))

    # Witness data — only walk past it; extraction is in caller.
    witnesses: list[list[bytes]] = []
    if has_witness:
        for _ in range(n_in):
            stack_size = rdr.varint()
            stack: list[bytes] = []
            for _ in range(stack_size):
                item_len = rdr.varint()
                stack.append(rdr.take(item_len))
            witnesses.append(stack)
    locktime = int.from_bytes(rdr.take(4), "little")

    tx = Transaction(
        version=version,
        inputs=tuple(inputs),
        outputs=tuple(outputs),
        locktime=locktime,
        has_witness=has_witness,
    )
    # Stash scriptsigs/witnesses on the side via attributes — frozen dataclass
    # has slots, so we cache them on a parallel structure the caller knows
    # how to reach.
    _PARSED_AUX[id(tx)] = _ParseAux(
        scriptsigs=tuple(input_scriptsigs),
        witnesses=tuple(tuple(w) for w in witnesses),
    )
    return tx


@dataclass(frozen=True, slots=True)
class _ParseAux:
    scriptsigs: tuple[bytes, ...]
    witnesses: tuple[tuple[bytes, ...], ...]


# Process-local stash — keyed by id(transaction). This is intentionally simple
# (no LRU, no thread safety) because each ``extract_outgoing_signatures`` call
# parses a fixed set of transactions and discards them.
_PARSED_AUX: dict[int, _ParseAux] = {}


# ---------------------------------------------------------------------------
# Per-input signature parsing
# ---------------------------------------------------------------------------
def _parse_p2pkh_input(scriptsig: bytes) -> tuple[bytes, bytes] | None:
    """Return (DER signature, compressed pubkey) from a P2PKH scriptSig.

    Standard layout: ``<sig-len> <sig> <pubkey-len> <pubkey>``. Returns
    ``None`` if the script doesn't match (multisig, unknown script).
    """
    if not scriptsig:
        return None
    pos = 0
    sig_len = scriptsig[pos]
    pos += 1
    if sig_len == 0 or pos + sig_len > len(scriptsig):
        return None
    sig = scriptsig[pos : pos + sig_len]
    pos += sig_len
    if pos >= len(scriptsig):
        return None
    pk_len = scriptsig[pos]
    pos += 1
    if pos + pk_len != len(scriptsig):
        return None
    pubkey = scriptsig[pos : pos + pk_len]
    if pk_len not in (33, 65):
        return None
    return sig, pubkey


def _parse_p2wpkh_witness(witness: tuple[bytes, ...]) -> tuple[bytes, bytes] | None:
    """Return (DER signature, compressed pubkey) from a P2WPKH witness stack."""
    if len(witness) != 2:
        return None
    sig, pubkey = witness
    if len(pubkey) != 33:
        return None
    return sig, pubkey


def _split_sig_and_sighash(sig_with_type: bytes) -> tuple[bytes, int] | None:
    """Split DER+sighash byte: signature is everything except the last byte."""
    if len(sig_with_type) < 2:
        return None
    return sig_with_type[:-1], sig_with_type[-1]


def _hash160(data: bytes) -> bytes:
    """Return the RIPEMD-160 of SHA-256 (Bitcoin "hash160")."""
    import hashlib

    return hashlib.new("ripemd160", hashlib.sha256(data).digest()).digest()


# ---------------------------------------------------------------------------
# Public extraction API
# ---------------------------------------------------------------------------
def extract_outgoing_signatures(
    address: str,
    client: MempoolClient,
    *,
    max_txs: int = 200,
) -> list[SignatureRecord]:
    """Return the ``(r, s, pubkey, z)`` records for every outgoing tx.

    Args:
        address: P2PKH (1...) or P2WPKH (bc1q...) address. P2SH-wrapped
            segwit is *not* supported in v1.0 — those inputs are skipped
            with a WARNING.
        client: anything implementing :class:`MempoolClient`.
        max_txs: hard cap to keep audits bounded (mempool.space paginates
            in batches of 25; we walk the first ``max_txs / 25`` pages).

    Returns:
        Flat list of :class:`SignatureRecord`.
    """
    summaries = client.get_address_txs(address)
    out: list[SignatureRecord] = []

    for tx_summary in summaries[:max_txs]:
        txid = str(tx_summary.get("txid", ""))
        if not txid:
            continue
        try:
            raw_hex = client.get_raw_tx_hex(txid)
        except (httpx.HTTPError, RuntimeError) as exc:
            log.warning("skipping txid=%s: cannot fetch raw hex (%s)", txid, exc)
            continue

        tx = _parse_raw_tx(raw_hex)
        aux = _PARSED_AUX.pop(id(tx), None)

        # Each tx_summary's ``vin`` describes the spent prevout — we use it
        # to know whether a given input spends *our* address.
        vin_list: object = tx_summary.get("vin")
        if not isinstance(vin_list, list):
            continue

        vin_list_typed: list[object] = list(vin_list)  # pyright: ignore[reportUnknownArgumentType]
        for vin_index, vin in enumerate(vin_list_typed):
            if not isinstance(vin, dict):
                continue
            vin_dict: dict[str, object] = vin  # pyright: ignore[reportUnknownVariableType,reportAssignmentType]
            prev_obj = vin_dict.get("prevout")
            if not isinstance(prev_obj, dict):
                continue
            prev: dict[str, object] = prev_obj  # pyright: ignore[reportUnknownVariableType,reportAssignmentType]
            prev_addr = prev.get("scriptpubkey_address")
            if prev_addr != address:
                continue  # this input doesn't spend our address
            prev_value_obj = prev.get("value")
            if not isinstance(prev_value_obj, int):
                continue
            prev_value = prev_value_obj
            script_type_obj = prev.get("scriptpubkey_type")
            script_type = (
                "p2pkh"
                if script_type_obj == "p2pkh"
                else "p2wpkh"
                if script_type_obj == "v0_p2wpkh"
                else None
            )
            if script_type is None:
                log.warning(
                    "skipping %s:%d: unsupported script %s",
                    txid,
                    vin_index,
                    script_type_obj,
                )
                continue

            if aux is None:
                continue

            if script_type == "p2pkh":
                pair = _parse_p2pkh_input(aux.scriptsigs[vin_index])
            else:
                pair = _parse_p2wpkh_witness(aux.witnesses[vin_index])
            if pair is None:
                log.warning("skipping %s:%d: cannot parse signature stack", txid, vin_index)
                continue
            sig_with_type, pubkey = pair
            split = _split_sig_and_sighash(sig_with_type)
            if split is None:
                continue
            der_sig, sighash_type = split
            if sighash_type != SIGHASH_ALL:
                log.warning(
                    "skipping %s:%d: unsupported sighash 0x%02x", txid, vin_index, sighash_type
                )
                continue

            try:
                r, s = parse_der(der_sig)
            except DERParseError as exc:
                log.warning("skipping %s:%d: malformed DER (%s)", txid, vin_index, exc)
                continue

            # Compute z for this input.
            try:
                if script_type == "p2pkh":
                    spk_obj = prev.get("scriptpubkey", "")
                    spk_hex = spk_obj if isinstance(spk_obj, str) else ""
                    spk = bytes.fromhex(spk_hex)
                    z = legacy_sighash_all(tx, vin_index, spk)
                else:
                    z = bip143_sighash_all_p2wpkh(
                        tx,
                        input_index=vin_index,
                        prev_value=prev_value,
                        prev_pkh=_hash160(pubkey),
                    )
            except (ValueError, IndexError) as exc:
                log.warning("skipping %s:%d: sighash failed (%s)", txid, vin_index, exc)
                continue

            out.append(
                SignatureRecord(
                    txid=txid,
                    vin_index=vin_index,
                    pubkey_compressed=pubkey,
                    r=r,
                    s=s,
                    z=z,
                    sighash_type=sighash_type,
                    script_type=script_type,
                )
            )

    return out


def signature_records_from_iter(it: Iterable[SignatureRecord]) -> list[SignatureRecord]:
    """Coerce an iterable of records to a list (helper for tests)."""
    return list(it)


__all__ = [
    "HttpMempoolClient",
    "MempoolClient",
    "SignatureRecord",
    "extract_outgoing_signatures",
    "signature_records_from_iter",
]
