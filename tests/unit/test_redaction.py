"""Unit tests for the structlog redaction processors."""

from __future__ import annotations

import pytest

from wallet_self_audit.logging.redaction import (
    ALLOWLIST_FIELDS,
    RedactionFailClosed,
    allowlist_filter,
    fail_closed_guard,
    suspect_hex_scrub,
)


# ---------------------------------------------------------------------------
# allowlist_filter
# ---------------------------------------------------------------------------
def test_allowlist_drops_unknown_field() -> None:
    out = allowlist_filter(None, "info", {"event": "x", "address": "bc1q...", "privkey": "secret"})
    assert "privkey" not in out
    assert out["address"] == "bc1q..."


def test_allowlist_keeps_all_allowed_fields() -> None:
    sample = dict.fromkeys(ALLOWLIST_FIELDS, "v")
    out = allowlist_filter(None, "info", sample)
    assert set(out.keys()) == ALLOWLIST_FIELDS


def test_allowlist_empty_dict() -> None:
    assert allowlist_filter(None, "info", {}) == {}


# ---------------------------------------------------------------------------
# suspect_hex_scrub
# ---------------------------------------------------------------------------
def test_scrub_redacts_64hex_in_non_txid_field() -> None:
    out = suspect_hex_scrub(None, "info", {"recommendation": "data " + "a" * 64 + " trailing"})
    assert "[REDACTED:HEX64]" in out["recommendation"]
    assert "a" * 64 not in out["recommendation"]


def test_scrub_preserves_64hex_in_txid_field() -> None:
    """txid legitimately contains 64-hex; must not be redacted."""
    txid = "a" * 64
    out = suspect_hex_scrub(None, "info", {"txid": txid})
    assert out["txid"] == txid


def test_scrub_redacts_long_hex() -> None:
    out = suspect_hex_scrub(None, "info", {"x": "a" * 128})
    assert "[REDACTED:LONG-HEX]" in out["x"]


def test_scrub_redacts_bip39_pattern() -> None:
    mnemonic = (
        "abandon ability able about above absent absorb abstract absurd abuse access accident"
    )
    out = suspect_hex_scrub(None, "info", {"x": mnemonic})
    assert out["x"] == "[REDACTED:BIP39]"


def test_scrub_redacts_wif() -> None:
    wif = "L1aW4aubDFB7yfras2S1mN3bqg9nwySY8nkoLmJebSLD5BWv3ENZ"
    out = suspect_hex_scrub(None, "info", {"x": wif})
    assert "[REDACTED:WIF]" in out["x"]


def test_scrub_redacts_xprv() -> None:
    xprv = "xprv" + "1" * 107
    out = suspect_hex_scrub(None, "info", {"x": xprv})
    assert "[REDACTED:XPRV]" in out["x"]


def test_scrub_passes_non_string_unchanged() -> None:
    out = suspect_hex_scrub(None, "info", {"count": 42, "ratio": 0.5})
    assert out == {"count": 42, "ratio": 0.5}


# ---------------------------------------------------------------------------
# fail_closed_guard
# ---------------------------------------------------------------------------
def test_guard_passes_clean_input() -> None:
    safe = {"address": "bc1qexample", "status": "SAFE", "count": 42}
    out = fail_closed_guard(None, "info", safe)
    assert out == safe


def test_guard_raises_on_long_hex() -> None:
    with pytest.raises(RedactionFailClosed, match="128"):
        fail_closed_guard(None, "info", {"x": "a" * 128})


def test_guard_raises_on_bip39() -> None:
    mnemonic = (
        "abandon ability able about above absent absorb abstract absurd abuse access accident"
    )
    with pytest.raises(RedactionFailClosed, match="BIP-39"):
        fail_closed_guard(None, "info", {"x": mnemonic})


def test_guard_raises_on_wif() -> None:
    with pytest.raises(RedactionFailClosed, match="WIF"):
        fail_closed_guard(
            None,
            "info",
            {"x": "L1aW4aubDFB7yfras2S1mN3bqg9nwySY8nkoLmJebSLD5BWv3ENZ"},
        )


def test_guard_raises_on_xprv() -> None:
    with pytest.raises(RedactionFailClosed, match="xprv"):
        fail_closed_guard(None, "info", {"x": "xprv" + "1" * 107})


def test_guard_handles_list_values() -> None:
    """fail_closed_guard must scan list/tuple values too."""
    with pytest.raises(RedactionFailClosed):
        fail_closed_guard(None, "info", {"items": ["safe", "a" * 128]})
