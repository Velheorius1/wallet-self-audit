"""Unit tests for ``prng.milk_sad`` — synthetic vulnerable wallet detection."""

from __future__ import annotations

import os

import pytest

from wallet_self_audit.prng.derive import first_addresses
from wallet_self_audit.prng.milk_sad import (
    MilkSadHit,
    scan_window,
    scan_window_by_addresses,
)
from wallet_self_audit.prng.mt19937_cpp import entropy_from_timestamp


def test_scan_window_finds_synthetic_hit() -> None:
    """Plant a synthetic vulnerable wallet at a known timestamp."""
    target_ts = 1577836900
    target_entropy = entropy_from_timestamp(target_ts, n_words=12)

    hit = scan_window(target_entropy, start=target_ts - 50, end=target_ts + 50, n_workers=1)
    assert hit is not None
    assert isinstance(hit, MilkSadHit)
    assert hit.timestamp == target_ts
    assert hit.matched_via == "entropy"


def test_scan_window_random_entropy_misses() -> None:
    """Random entropy should not match in a 100-second Milk Sad window."""
    target_ts = 1577836900
    rand = os.urandom(16)
    miss = scan_window(rand, start=target_ts - 50, end=target_ts + 50, n_workers=1)
    assert miss is None


def test_scan_window_empty_window_returns_none() -> None:
    rand = os.urandom(16)
    assert scan_window(rand, start=1000, end=1000, n_workers=1) is None


def test_scan_window_invalid_entropy_length() -> None:
    with pytest.raises(ValueError, match="unsupported entropy length"):
        scan_window(b"\x00" * 17, start=0, end=10, n_workers=1)


def test_scan_window_by_addresses_finds_synthetic_hit() -> None:
    """Plant a synthetic Milk Sad timestamp; address-only scan should find it."""
    target_ts = 1577836900
    target_entropy = entropy_from_timestamp(target_ts, n_words=12)
    addrs = first_addresses(target_entropy)
    # Use the bech32 address as the searched target.
    targets = frozenset({addrs.p2wpkh_bip84}) if addrs.p2wpkh_bip84 else frozenset()

    hit = scan_window_by_addresses(targets, start=target_ts - 5, end=target_ts + 5, n_workers=1)
    assert hit is not None
    assert hit.timestamp == target_ts
    assert hit.matched_via == "p2wpkh_bip84"


def test_scan_window_by_addresses_empty_targets_raises() -> None:
    with pytest.raises(ValueError, match="non-empty"):
        scan_window_by_addresses(frozenset(), start=0, end=10, n_workers=1)
