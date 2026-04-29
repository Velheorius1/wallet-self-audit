"""Integration tests for BIP-322 ownership proof verification.

Test corpus is loaded from ``tests/fixtures/bip322/corpus.json``. Each entry
has ``address``, ``message`` (challenge), ``signature`` (proof, base64), and
``expected`` (true/false for verify outcome).

Bypass the time-bound TTL by using an explicit ``issued_at`` parsed from the
challenge — corpus messages don't follow our challenge format, so we wrap
them through a custom proof that skips parse_challenge.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from wallet_self_audit.ownership import (
    BIP322Proof,
    classify_address,
    is_challenge_expired,
    make_challenge,
    parse_challenge,
)

_CORPUS = Path(__file__).resolve().parent.parent / "fixtures" / "bip322" / "corpus.json"


@pytest.mark.integration
def test_corpus_loads() -> None:
    """Corpus file exists and contains ≥ 5 vectors."""
    assert _CORPUS.exists(), f"corpus not found: {_CORPUS}"
    data = json.loads(_CORPUS.read_text(encoding="utf-8"))
    assert "vectors" in data
    assert len(data["vectors"]) >= 5, f"need ≥5 vectors, got {len(data['vectors'])}"


@pytest.mark.integration
def test_corpus_addresses_classify() -> None:
    """Every vector's address must classify cleanly (not 'unknown')."""
    if not _CORPUS.exists():
        pytest.skip("corpus not generated yet")
    data = json.loads(_CORPUS.read_text(encoding="utf-8"))
    for v in data["vectors"]:
        addr = v["address"]
        kind = classify_address(addr)
        assert kind != "unknown", f"address {addr!r} classified as unknown"


@pytest.mark.integration
def test_corpus_verify_via_bip322(monkeypatch) -> None:
    """Verify each corpus vector via the bip322 library (when installed).

    The corpus is the canonical cross-wallet truth. If bip322 isn't
    installed, this test is skipped with a clear message.
    """
    bip322 = pytest.importorskip("bip322", reason="bip322 lib not installed")
    if not _CORPUS.exists():
        pytest.skip("corpus not generated yet")

    data = json.loads(_CORPUS.read_text(encoding="utf-8"))
    failures: list[str] = []
    for v in data["vectors"]:
        addr = v["address"]
        msg = v["message"]
        sig_bytes = base64.b64decode(v["signature"])
        try:
            verified = bool(bip322.verify_simple(addr, msg, sig_bytes))
        except Exception as exc:
            verified = False
            failures.append(f"{v['source']}: {addr} -> exception {exc!r}")
            continue
        if verified != v["expected"]:
            failures.append(
                f"{v['source']}: {addr} -> got {verified}, expected {v['expected']}"
            )

    if failures:
        pytest.fail("\n".join(failures))


# ---------------------------------------------------------------------------
# Challenge generation / parsing
# ---------------------------------------------------------------------------
def test_make_challenge_format() -> None:
    addr = "bc1qexample0000000000000000000000000000000"
    ch = make_challenge(addr)
    parts = ch.split("::")
    assert parts[0] == "wallet-self-audit"
    assert parts[1] == "v1"
    assert parts[2] == addr
    # parts[3] = ISO timestamp; parts[4] = 64-char hex nonce.
    assert len(parts[4]) == 64


def test_make_challenge_unique_nonces() -> None:
    addr = "bc1qexample"
    a = make_challenge(addr)
    b = make_challenge(addr)
    assert a != b


def test_parse_challenge_round_trip() -> None:
    addr = "bc1qexample"
    ch = make_challenge(addr)
    parsed_addr, ts = parse_challenge(ch)
    assert parsed_addr == addr
    assert ts.tzinfo is not None  # must be UTC-aware


@pytest.mark.parametrize(
    "bad_challenge",
    [
        "wrong-prefix::v1::addr::2026-04-29T00:00:00+00:00::nonce",
        "wallet-self-audit::v0::addr::2026-04-29T00:00:00+00:00::nonce",
        "wallet-self-audit::v1::addr::not-a-timestamp::nonce",
        "wallet-self-audit::v1::addr::2026-04-29::nonce",  # naive
        "too::few::parts",
    ],
)
def test_parse_malformed_challenge_raises(bad_challenge: str) -> None:
    with pytest.raises(ValueError):
        parse_challenge(bad_challenge)


def test_expired_challenge_detected() -> None:
    """A challenge older than 24h must be flagged expired."""
    from datetime import datetime, timedelta, timezone

    issued = datetime.now(timezone.utc) - timedelta(hours=25)
    assert is_challenge_expired(issued)


def test_fresh_challenge_not_expired() -> None:
    from datetime import datetime, timezone

    issued = datetime.now(timezone.utc)
    assert not is_challenge_expired(issued)


# ---------------------------------------------------------------------------
# Address classification
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "addr,expected",
    [
        ("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "p2pkh"),
        ("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy", "p2sh_p2wpkh"),
        ("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", "p2wpkh"),
        ("bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3", "p2wsh"),
        (
            "bc1pmzfrwwndsqmk5yh69yjr5lfgfg4ev8c0tsc06e",
            "p2tr",
        ),
        ("not-an-address", "unknown"),
        ("", "unknown"),
    ],
)
def test_classify_address(addr: str, expected: str) -> None:
    assert classify_address(addr) == expected


# ---------------------------------------------------------------------------
# Replay store
# ---------------------------------------------------------------------------
def test_proof_with_expired_challenge_raises(tmp_path) -> None:
    """A proof referencing an expired challenge raises before calling bip322."""
    from datetime import datetime, timedelta, timezone

    addr = "bc1qexample"
    expired_ts = (datetime.now(timezone.utc) - timedelta(hours=25)).isoformat(
        timespec="seconds"
    )
    expired_challenge = f"wallet-self-audit::v1::{addr}::{expired_ts}::{'a' * 64}"

    proof = BIP322Proof(
        method="bip322",
        address=addr,
        challenge=expired_challenge,
        proof=b"\x00",  # any
        replay_store_path=tmp_path / "replay.jsonl",
    )

    with pytest.raises(ValueError, match="expired"):
        proof.verify()


def test_proof_with_address_mismatch_raises(tmp_path) -> None:
    """Challenge address must match proof address."""
    challenge = make_challenge("bc1qaddrA")
    proof = BIP322Proof(
        method="bip322",
        address="bc1qaddrB",
        challenge=challenge,
        proof=b"\x00",
        replay_store_path=tmp_path / "replay.jsonl",
    )
    with pytest.raises(ValueError, match="address does not match"):
        proof.verify()


def test_proof_with_unknown_address_raises(tmp_path) -> None:
    """Unsupported address types must be rejected, not silent-fallback."""
    challenge = make_challenge("foo-bar-not-an-address")
    proof = BIP322Proof(
        method="bip322",
        address="foo-bar-not-an-address",
        challenge=challenge,
        proof=b"\x00",
        replay_store_path=tmp_path / "replay.jsonl",
    )
    with pytest.raises(ValueError, match="unsupported address type"):
        proof.verify()
