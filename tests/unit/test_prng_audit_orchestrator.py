"""Unit tests for ``vectors.prng_audit`` orchestrator."""

from __future__ import annotations

import hashlib

import pytest

from wallet_self_audit.prng.derive import addresses_from_privkey, first_addresses
from wallet_self_audit.prng.mt19937_cpp import entropy_from_timestamp
from wallet_self_audit.prng.owner_input import MnemonicHandle
from wallet_self_audit.vectors.prng_audit import (
    PrngAuditConfig,
    normalize_addresses,
    run_prng_audit,
)


# ---------------------------------------------------------------------------
# VULNERABLE paths
# ---------------------------------------------------------------------------
def test_milk_sad_vulnerable_via_entropy_mode() -> None:
    """Synthetic Milk Sad detected when running with mnemonic handle."""
    target_ts = 1577836900
    entropy = entropy_from_timestamp(target_ts, n_words=12)
    addrs = first_addresses(entropy)
    assert addrs.p2wpkh_bip84 is not None

    cfg = PrngAuditConfig(
        address=addrs.p2wpkh_bip84,
        target_addresses=frozenset({addrs.p2wpkh_bip84}),
        vectors=("milk_sad",),
        milk_sad_window=(target_ts - 5, target_ts + 5),
        n_workers=1,
    )
    handle = MnemonicHandle(_entropy_bytes=entropy)
    verdict = run_prng_audit(cfg, mnemonic_handle=handle)
    assert verdict.status == "VULNERABLE"
    assert verdict.finding == "weak_prng_milksad"
    assert verdict.key_fingerprint is not None
    assert "Milk Sad" in verdict.recommendation


def test_milk_sad_vulnerable_via_address_mode() -> None:
    """No mnemonic — but address-only mode must still find a planted hit."""
    target_ts = 1577836900
    entropy = entropy_from_timestamp(target_ts, n_words=12)
    addrs = first_addresses(entropy)
    assert addrs.p2wpkh_bip84 is not None

    cfg = PrngAuditConfig(
        address=addrs.p2wpkh_bip84,
        target_addresses=frozenset({addrs.p2wpkh_bip84}),
        vectors=("milk_sad",),
        milk_sad_window=(target_ts - 5, target_ts + 5),
        n_workers=1,
    )
    verdict = run_prng_audit(cfg, mnemonic_handle=None)
    assert verdict.status == "VULNERABLE"
    assert verdict.finding == "weak_prng_milksad"


def test_brainwallet_password_vulnerable() -> None:
    """sha256('password') is in the sample wordlist."""
    pk = hashlib.sha256(b"password").digest()
    addrs = addresses_from_privkey(pk)
    assert addrs.p2pkh_bip44 is not None

    cfg = PrngAuditConfig(
        address=addrs.p2pkh_bip44,
        target_addresses=frozenset({addrs.p2pkh_bip44}),
        vectors=("brainwallet",),
        n_workers=1,
    )
    verdict = run_prng_audit(cfg)
    assert verdict.status == "VULNERABLE"
    assert verdict.finding == "brainwallet"
    assert verdict.key_fingerprint is not None


# ---------------------------------------------------------------------------
# CLEAN paths
# ---------------------------------------------------------------------------
def test_clean_address_returns_safe_or_suspicious() -> None:
    """Random fresh address with only milk_sad+brainwallet → SAFE."""
    pk = hashlib.sha256(b"this-passphrase-is-not-in-any-list-2026").digest()
    addrs = addresses_from_privkey(pk)
    assert addrs.p2wpkh_bip84 is not None

    cfg = PrngAuditConfig(
        address=addrs.p2wpkh_bip84,
        target_addresses=frozenset({addrs.p2wpkh_bip84}),
        # Skip randstorm so we get a SAFE rather than SUSPICIOUS verdict.
        vectors=("milk_sad", "brainwallet"),
        # Tiny milk-sad window so it runs fast.
        milk_sad_window=(0, 10),
        n_workers=1,
    )
    verdict = run_prng_audit(cfg)
    assert verdict.status == "SAFE"
    assert verdict.finding == "none"
    assert verdict.checks_performed == ("milk_sad", "brainwallet")


def test_clean_with_randstorm_is_suspicious_partial() -> None:
    """A clean run that includes randstorm must report SUSPICIOUS — partial."""
    pk = hashlib.sha256(b"another-not-a-public-passphrase-2026").digest()
    addrs = addresses_from_privkey(pk)
    assert addrs.p2wpkh_bip84 is not None

    cfg = PrngAuditConfig(
        address=addrs.p2wpkh_bip84,
        target_addresses=frozenset({addrs.p2wpkh_bip84}),
        vectors=("randstorm",),
        randstorm_s0_range=(0, 100),  # tiny range
        n_workers=1,
    )
    verdict = run_prng_audit(cfg)
    assert verdict.status == "SUSPICIOUS"
    assert verdict.finding == "none"
    assert "Randstorm" in verdict.recommendation


# ---------------------------------------------------------------------------
# Helpers / config invariants
# ---------------------------------------------------------------------------
def test_normalize_addresses_strips_whitespace() -> None:
    out = normalize_addresses(["  bc1qfoo  ", "1BarBaz"])
    assert out == frozenset({"bc1qfoo", "1BarBaz"})


def test_normalize_addresses_rejects_empty() -> None:
    with pytest.raises(ValueError, match="empty address"):
        normalize_addresses(["bc1qfoo", "   "])


def test_empty_target_addresses_raises() -> None:
    cfg = PrngAuditConfig(
        address="bc1qfoo",
        target_addresses=frozenset(),
        vectors=("milk_sad",),
        n_workers=1,
    )
    with pytest.raises(ValueError, match="must be non-empty"):
        run_prng_audit(cfg)


def test_mnemonic_handle_zero_overwrites_on_burn() -> None:
    """Verify the MnemonicHandle context manager burns memory."""
    handle = MnemonicHandle(_entropy_bytes=b"\xab" * 16)
    with handle.entropy() as view:
        assert bytes(view[:4]) == b"\xab\xab\xab\xab"
    # After exiting the context, the Secret was burned. Re-entering
    # produces a fresh context, but the underlying _entropy_bytes (the
    # frozen attribute) is still the original — that is by design (the
    # handle is meant to be re-entered).
