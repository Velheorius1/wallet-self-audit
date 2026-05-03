"""Unit tests for ``lattice.lll_pure`` — pure-Python LLL with Fraction math."""

from __future__ import annotations

from fractions import Fraction

import pytest

from wallet_self_audit.lattice.lll_pure import lll_reduce, round_half_to_even


# ---------------------------------------------------------------------------
# round_half_to_even — banker's rounding.
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("x", "expected"),
    [
        (Fraction(0), 0),
        (Fraction(1, 2), 0),  # tie → even (0)
        (Fraction(3, 2), 2),  # tie → even (2)
        (Fraction(5, 2), 2),  # tie → even (2)
        (Fraction(7, 4), 2),  # 1.75 → 2
        (Fraction(-1, 2), 0),  # -0.5 → tie → even (0)
        (Fraction(-3, 2), -2),  # -1.5 → tie → even (-2)
        (Fraction(-5, 2), -2),  # -2.5 → tie → even (-2)
        (Fraction(7, 8), 1),  # 0.875 → 1
        (Fraction(-7, 8), -1),  # -0.875 → -1
        (Fraction(2), 2),
        (Fraction(-3), -3),
    ],
)
def test_round_half_to_even(x: Fraction, expected: int) -> None:
    assert round_half_to_even(x) == expected


# ---------------------------------------------------------------------------
# LLL reduction — sanity properties.
# ---------------------------------------------------------------------------
def _det3(b: list[list[Fraction]]) -> Fraction:
    a, c, d = b[0]
    e, f, g = b[1]
    h, i, j = b[2]
    return a * (f * j - g * i) - c * (e * j - g * h) + d * (e * i - f * h)


def test_lll_preserves_lattice_determinant() -> None:
    basis = [
        [Fraction(1), Fraction(1), Fraction(1)],
        [Fraction(-1), Fraction(0), Fraction(2)],
        [Fraction(3), Fraction(5), Fraction(6)],
    ]
    reduced = lll_reduce(basis)
    # Lattices preserve abs(det) under unimodular transforms — and LLL is
    # unimodular by construction.
    assert abs(_det3(basis)) == abs(_det3(reduced))


def test_lll_first_row_is_short() -> None:
    """The first row after reduction should be shorter than the original."""
    basis = [
        [Fraction(105), Fraction(821), Fraction(404)],
        [Fraction(11), Fraction(34), Fraction(67)],
        [Fraction(72), Fraction(101), Fraction(220)],
    ]
    reduced = lll_reduce(basis)

    def norm_sq(v: list[Fraction]) -> Fraction:
        return sum((x * x for x in v), Fraction(0))

    # The first reduced row should be no longer than the shortest original.
    shortest_original = min(norm_sq(row) for row in basis)
    assert norm_sq(reduced[0]) <= shortest_original


def test_lll_empty_basis() -> None:
    assert lll_reduce([]) == []


def test_lll_single_row() -> None:
    basis = [[Fraction(3), Fraction(5), Fraction(7)]]
    out = lll_reduce(basis)
    assert out == basis


def test_lll_rejects_ragged_basis() -> None:
    with pytest.raises(ValueError, match="same length"):
        lll_reduce([[Fraction(1), Fraction(2)], [Fraction(3)]])


def test_lll_does_not_mutate_input() -> None:
    basis = [
        [Fraction(1), Fraction(1), Fraction(1)],
        [Fraction(-1), Fraction(0), Fraction(2)],
        [Fraction(3), Fraction(5), Fraction(6)],
    ]
    snapshot = [list(row) for row in basis]
    _ = lll_reduce(basis)
    assert basis == snapshot
