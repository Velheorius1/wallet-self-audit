"""Unit tests for ``prng.randstorm`` — synthetic V8 MWC seed detection."""

from __future__ import annotations

import os

import pytest

from wallet_self_audit.prng.randstorm import (
    RandstormHit,
    ScanCoverage,
    _v8_mwc_entropy,
    scan_seeds,
)


def test_scan_seeds_finds_synthetic_hit() -> None:
    """Plant a synthetic vulnerable wallet at a known V8 (s0, s1)."""
    s0_target = 0x1234
    s1_target = 0xCAFE0000
    target_entropy = _v8_mwc_entropy(s0_target, s1_target, 16)

    hit, coverage = scan_seeds(
        target_entropy,
        s0_range=(s0_target - 5, s0_target + 5),
        s1_fixed=s1_target,
        n_workers=1,
    )
    assert hit is not None
    assert isinstance(hit, RandstormHit)
    assert hit.s0_seed == s0_target
    assert hit.s1_seed == s1_target
    assert hit.matched_via == "entropy"
    assert isinstance(coverage, ScanCoverage)
    assert coverage.v8_mwc_dominant is True


def test_scan_seeds_random_entropy_misses() -> None:
    rand = os.urandom(16)
    hit, _ = scan_seeds(
        rand, s0_range=(0, 100), s1_fixed=0xCAFE0000, n_workers=1
    )
    assert hit is None


def test_scan_seeds_invalid_entropy_length() -> None:
    with pytest.raises(ValueError, match="unsupported entropy length"):
        scan_seeds(b"\x00" * 17, s0_range=(0, 10), n_workers=1)


def test_scan_seeds_coverage_struct_exposes_range() -> None:
    rand = os.urandom(16)
    _, cov = scan_seeds(rand, s0_range=(0, 50), n_workers=1)
    assert cov.s0_range == (0, 50)
    assert "V8 MWC" in cov.note
