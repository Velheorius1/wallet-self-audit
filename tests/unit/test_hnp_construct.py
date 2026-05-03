"""Unit tests for ``lattice.hnp_construct`` — basis builder."""

from __future__ import annotations

from fractions import Fraction

import pytest

from wallet_self_audit.lattice.hnp_construct import (
    SECP256K1_N,
    HnpHypothesis,
    build_top_bits_zero_basis,
    candidate_d_from_short_vector,
    min_signatures_required,
)


def test_min_signatures_required_thresholds() -> None:
    assert min_signatures_required(8) == 33
    assert min_signatures_required(4) == 70
    assert min_signatures_required(2) == 140
    assert min_signatures_required(1) == 220


def test_min_signatures_required_caps_at_8() -> None:
    """Bias bits >= 8 all use the smallest threshold (33)."""
    assert min_signatures_required(16) == 33
    assert min_signatures_required(64) == 33


def test_min_signatures_required_zero_or_negative() -> None:
    with pytest.raises(ValueError, match=">= 1"):
        min_signatures_required(0)
    with pytest.raises(ValueError, match=">= 1"):
        min_signatures_required(-3)


def test_min_signatures_intermediate_bias() -> None:
    """Non-table values round up to the next threshold."""
    assert min_signatures_required(3) == 70  # rounds up to 4
    assert min_signatures_required(5) == 33  # rounds up to 8
    assert min_signatures_required(7) == 33  # rounds up to 8


def test_build_basis_dimensions() -> None:
    """For m sigs, basis is (m+2) x (m+2)."""
    sigs = [(11, 22, 33), (44, 55, 66), (77, 88, 99)]
    b = build_top_bits_zero_basis(sigs, bias_bits=8)
    assert len(b) == len(sigs) + 2
    for row in b:
        assert len(row) == len(sigs) + 2


def test_build_basis_diagonal_block() -> None:
    """Top m rows are 2^L · n · I_m."""
    sigs = [(11, 22, 33), (44, 55, 66)]
    b = build_top_bits_zero_basis(sigs, bias_bits=4)
    pow_l = 16
    for i in range(len(sigs)):
        for j in range(len(b[0])):
            if i == j:
                assert b[i][j] == Fraction(pow_l * SECP256K1_N)
            else:
                assert b[i][j] == Fraction(0)


def test_build_basis_empty_sigs_raises() -> None:
    with pytest.raises(ValueError, match="at least one"):
        build_top_bits_zero_basis([], bias_bits=8)


def test_build_basis_invalid_bias() -> None:
    with pytest.raises(ValueError, match=">= 1"):
        build_top_bits_zero_basis([(1, 2, 3)], bias_bits=0)


def test_candidate_from_short_vector_rejects_non_integer() -> None:
    vec = [Fraction(1), Fraction(2), Fraction(3, 2), Fraction(4)]
    assert candidate_d_from_short_vector(vec) is None


def test_candidate_from_short_vector_rejects_zero() -> None:
    vec = [Fraction(1), Fraction(2), Fraction(0), Fraction(0)]
    assert candidate_d_from_short_vector(vec) is None


def test_candidate_from_short_vector_returns_int() -> None:
    vec = [Fraction(1), Fraction(2), Fraction(0xC0FFEE), Fraction(0)]
    out = candidate_d_from_short_vector(vec)
    assert out == 0xC0FFEE


def test_candidate_from_short_vector_too_short() -> None:
    assert candidate_d_from_short_vector([Fraction(1)]) is None
    assert candidate_d_from_short_vector([]) is None


def test_hnp_hypothesis_dataclass_immutable() -> None:
    h = HnpHypothesis(name="top_bits_zero", bias_bits=8)
    with pytest.raises(AttributeError):
        h.bias_bits = 16  # type: ignore[misc]
