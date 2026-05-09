"""Offline ``MempoolClient`` for integration tests.

Loads a JSON fixture produced by ``tools/fetch_historical_fixture.py`` and
serves the same shape that ``HttpMempoolClient`` would. Tests can pass an
instance into ``extract_outgoing_signatures(address, client)`` with no
network access required.

The class structurally satisfies the ``MempoolClient`` Protocol from
``wallet_self_audit.nonce.extractor`` — Python duck-typing means we don't
inherit explicitly.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Self


class StaticMempoolClient:
    """Replays a recorded mempool.space response from a JSON file."""

    def __init__(self, fixture: dict[str, object]) -> None:
        address_obj = fixture.get("address")
        if not isinstance(address_obj, str):
            raise TypeError("fixture['address'] must be a string")
        self._address: str = address_obj

        address_txs_obj = fixture.get("address_txs")
        if not isinstance(address_txs_obj, list):
            raise TypeError("fixture['address_txs'] must be a list")
        self._address_txs: list[dict[str, object]] = []
        for t in address_txs_obj:  # pyright: ignore[reportUnknownVariableType]
            if isinstance(t, dict):
                self._address_txs.append(t)  # pyright: ignore[reportUnknownArgumentType]

        raw_txs_obj = fixture.get("raw_txs")
        if not isinstance(raw_txs_obj, dict):
            raise TypeError("fixture['raw_txs'] must be a dict")
        self._raw_txs: dict[str, str] = {}
        for k, v in raw_txs_obj.items():  # pyright: ignore[reportUnknownVariableType]
            if isinstance(k, str) and isinstance(v, str):
                self._raw_txs[k] = v

        tx_meta_obj = fixture.get("tx_meta")
        if not isinstance(tx_meta_obj, dict):
            raise TypeError("fixture['tx_meta'] must be a dict")
        self._tx_meta: dict[str, dict[str, object]] = {}
        for k, v in tx_meta_obj.items():  # pyright: ignore[reportUnknownVariableType]
            if isinstance(k, str) and isinstance(v, dict):
                self._tx_meta[k] = v  # pyright: ignore[reportUnknownArgumentType]

    @classmethod
    def from_path(cls, path: Path) -> Self:
        """Load the fixture from a JSON file path."""
        return cls(json.loads(path.read_text(encoding="utf-8")))

    @property
    def address(self) -> str:
        """The address recorded in the fixture (for tests that assert on it)."""
        return self._address

    # --- MempoolClient Protocol -----------------------------------------
    def get_address_txs(self, address: str) -> list[dict[str, object]]:
        if address != self._address:
            raise ValueError(
                f"StaticMempoolClient was loaded with address {self._address!r}, "
                f"asked for {address!r}",
            )
        return list(self._address_txs)

    def get_tx(self, txid: str) -> dict[str, object]:
        if txid not in self._tx_meta:
            raise KeyError(f"txid {txid!r} not in fixture")
        return self._tx_meta[txid]

    def get_raw_tx_hex(self, txid: str) -> str:
        if txid not in self._raw_txs:
            raise KeyError(f"raw tx {txid!r} not in fixture")
        return self._raw_txs[txid]


__all__ = ["StaticMempoolClient"]
