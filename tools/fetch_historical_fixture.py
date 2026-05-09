"""One-shot fetcher of mempool.space tx data for historical-collision tests.

Run this ONCE to download the on-chain transactions for a public historical
test vector, then commit the resulting JSON fixture. The
``StaticMempoolClient`` in ``tests/fixtures/nonce/static_client.py`` consumes
the fixture so integration tests run completely offline.

Two modes:

1. **Address mode** — walk the recent tx history of an address and capture
   all outgoing tx (those that spend FROM the address)::

       uv run python tools/fetch_historical_fixture.py \\
           --address 1ExampleAddress... \\
           --out tests/fixtures/nonce/historical.json

2. **Txid mode** — capture specific transactions by their txids. Use this
   for very old historical tx that don't appear in the first /txs page.
   The script fetches ``/tx/{txid}`` for the summary and
   ``/tx/{txid}/hex`` for the raw bytes::

       uv run python tools/fetch_historical_fixture.py \\
           --address 1ExampleAddress... \\
           --txid 9ec4bc49e828d924af1d1029cacf709431abbde46d59554b62bc270e3b29c4b1 \\
           --out tests/fixtures/nonce/historical.json

The script reuses ``HttpMempoolClient`` from the production extractor — no
new HTTP code is introduced for the test path.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

from wallet_self_audit.nonce.extractor import HttpMempoolClient

_DEFAULT_NOTE = (
    "Historical r-collision test vector. Public on-chain data only. "
    "Zero balance — funds long since drained. Used to validate Phase 3 "
    "verify-by-pubkey-projection math against a real-world incident."
)


def _spends_from(tx_summary: dict[str, object], address: str) -> bool:
    """True iff any vin of this tx_summary spends from ``address``.

    mempool.space returns each vin with a ``prevout`` that contains
    ``scriptpubkey_address``. Matching that to our address tells us this
    tx is an *outgoing* spend from the address (not just funding it).
    """
    vin_obj = tx_summary.get("vin")
    if not isinstance(vin_obj, list):
        return False
    for v in vin_obj:  # type: ignore[reportUnknownVariableType]
        if not isinstance(v, dict):
            continue
        prev_obj = v.get("prevout")
        if not isinstance(prev_obj, dict):
            continue
        if prev_obj.get("scriptpubkey_address") == address:
            return True
    return False


def _build_fixture(
    *,
    address: str,
    max_txs: int,
    note: str,
    explicit_txids: list[str],
) -> dict[str, object]:
    client = HttpMempoolClient()
    try:
        outgoing: list[dict[str, object]]
        if explicit_txids:
            print(
                f"[fetcher] txid mode: fetching {len(explicit_txids)} specific tx(s)",
                file=sys.stderr,
            )
            outgoing = []
            for i, txid in enumerate(explicit_txids, 1):
                print(f"[fetcher]   [{i}/{len(explicit_txids)}] {txid} (summary)", file=sys.stderr)
                tx_data = client.get_tx(txid)
                if not _spends_from(tx_data, address):
                    print(
                        f"[fetcher] ERROR: tx {txid} does not spend from {address}",
                        file=sys.stderr,
                    )
                    sys.exit(3)
                outgoing.append(tx_data)
        else:
            print(f"[fetcher] address mode: GET /address/{address}/txs", file=sys.stderr)
            summaries = client.get_address_txs(address)
            print(f"[fetcher]   got {len(summaries)} total summaries", file=sys.stderr)
            outgoing = [t for t in summaries if _spends_from(t, address)][:max_txs]
            print(
                f"[fetcher]   {len(outgoing)} are outgoing (spend FROM this address)",
                file=sys.stderr,
            )
            if not outgoing:
                print(
                    "[fetcher] ERROR: no outgoing tx — wrong address or zero spend history",
                    file=sys.stderr,
                )
                sys.exit(2)

        raw_txs: dict[str, str] = {}
        tx_meta: dict[str, dict[str, object]] = {}
        for i, tx in enumerate(outgoing, 1):
            txid_obj = tx.get("txid")
            if not isinstance(txid_obj, str) or not txid_obj:
                continue
            print(f"[fetcher]   [{i}/{len(outgoing)}] {txid_obj} (raw+meta)", file=sys.stderr)
            raw_txs[txid_obj] = client.get_raw_tx_hex(txid_obj)
            tx_meta[txid_obj] = client.get_tx(txid_obj)

        return {
            "address": address,
            "fetched_at": datetime.now(UTC).isoformat(),
            "source": "https://mempool.space/api",
            "note": note,
            "max_txs": max_txs,
            "explicit_txids": list(explicit_txids),
            "address_txs": outgoing,
            "raw_txs": raw_txs,
            "tx_meta": tx_meta,
        }
    finally:
        client.close()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Fetch mempool.space tx data for a historical test vector address.",
    )
    parser.add_argument("--address", required=True, help="Bitcoin address (P2PKH or P2WPKH)")
    parser.add_argument("--out", required=True, type=Path, help="Output JSON path")
    parser.add_argument(
        "--max-txs",
        type=int,
        default=200,
        help="Maximum outgoing tx to include (default: 200)",
    )
    parser.add_argument(
        "--note",
        default=_DEFAULT_NOTE,
        help="Free-form note embedded in fixture (provenance/incident reference)",
    )
    parser.add_argument(
        "--txid",
        action="append",
        default=[],
        help=(
            "Specific txid to capture (repeatable). When given, address mode is "
            "skipped — only these txids are fetched. Useful for very old tx "
            "that don't appear in the recent /txs page."
        ),
    )
    args = parser.parse_args()

    fixture = _build_fixture(
        address=str(args.address),
        max_txs=int(args.max_txs),
        note=str(args.note),
        explicit_txids=[str(t) for t in args.txid],
    )

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(fixture, indent=2, sort_keys=True))

    size_kb = out_path.stat().st_size // 1024
    raw_count = len(fixture["raw_txs"]) if isinstance(fixture["raw_txs"], dict) else 0
    print(
        f"[fetcher] saved {raw_count} outgoing tx → {out_path} ({size_kb} KB)",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
