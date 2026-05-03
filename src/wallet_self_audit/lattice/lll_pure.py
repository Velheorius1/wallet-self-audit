"""Pure-Python LLL lattice reduction with exact ``fractions.Fraction`` math.

Why pure Python:
- ``fpylll`` has fragile installation on Apple Silicon (gmp/mpfr/fplll
  build chain). We ship ``fpylll`` as an *optional* path; the default
  must always work with a vanilla ``uv sync``.
- Exact ``Fraction`` arithmetic avoids floating-point drift on the
  ill-conditioned bases that show up in HNP constructions for nonces
  with very small bias.

Algorithm: classic Lenstra-Lenstra-Lovász (1982) using rational Gram-
Schmidt orthogonalisation. Suitable for dimensions up to roughly 80;
beyond that, switch to ``fpylll`` / BKZ.

This module is dependency-free (only stdlib) so it imports fast and
runs everywhere. The price is speed: pure-Python arithmetic on
``Fraction`` is ~100x slower than numpy/Accelerate, but for the sizes
self-audit cares about (a few-hundred sig HNP) it is plenty fast.
"""

from __future__ import annotations

from fractions import Fraction
from typing import Final

# Lovász condition constant — the canonical 3/4 from the original paper.
# Higher (closer to 1) gives stronger reduction but slower convergence.
_DELTA: Final[Fraction] = Fraction(3, 4)


def _gs_orthogonalize(
    basis: list[list[Fraction]],
) -> tuple[list[list[Fraction]], list[list[Fraction]]]:
    """Compute the Gram-Schmidt orthogonalisation of ``basis`` (rationally).

    Returns:
        (b_star, mu) where ``b_star[i]`` is the i-th orthogonal vector and
        ``mu[i][j]`` is the GS coefficient ⟨b_i, b_star_j⟩ / ⟨b_star_j, b_star_j⟩.
    """
    n = len(basis)
    b_star: list[list[Fraction]] = [list(b) for b in basis]  # copies
    mu: list[list[Fraction]] = [[Fraction(0) for _ in range(n)] for _ in range(n)]

    for i in range(n):
        for j in range(i):
            # mu[i][j] = ⟨b_i, b_star_j⟩ / ⟨b_star_j, b_star_j⟩
            num = sum((basis[i][k] * b_star[j][k] for k in range(len(basis[i]))), Fraction(0))
            den = sum(
                (b_star[j][k] * b_star[j][k] for k in range(len(b_star[j]))),
                Fraction(0),
            )
            mu[i][j] = num / den if den != 0 else Fraction(0)
            for k in range(len(b_star[i])):
                b_star[i][k] -= mu[i][j] * b_star[j][k]

    return b_star, mu


def lll_reduce(basis: list[list[Fraction]]) -> list[list[Fraction]]:
    """Reduce ``basis`` in place via the classical LLL algorithm.

    Args:
        basis: List of basis row vectors. Each row must have the same
            length. Inputs are copied; the original list is unchanged.

    Returns:
        The LLL-reduced basis as a new list of new rows. The shortest
        vector candidate is in row 0 after reduction (no guarantee, but
        empirically always for HNP instances).

    Notes on dimensions:
        The reduction time scales as roughly O(n^4 · log B) where B is
        the largest basis-vector norm. For HNP constructions with 220
        signatures and 1-bit bias, n ≈ 220 — too slow for pure Python.
        For typical Phase-4 hypotheses (8-bit bias, ~33 sigs) n ≈ 33
        which finishes in well under a second on M-series.
    """
    if not basis:
        return []
    if any(len(row) != len(basis[0]) for row in basis):
        raise ValueError("all basis rows must have the same length")

    # Local copy so mutations don't leak.
    b: list[list[Fraction]] = [list(row) for row in basis]
    n = len(b)

    b_star, mu = _gs_orthogonalize(b)

    def _norm_sq(v: list[Fraction]) -> Fraction:
        return sum((x * x for x in v), Fraction(0))

    k = 1
    while k < n:
        # Size reduction.
        for j in range(k - 1, -1, -1):
            q = round_half_to_even(mu[k][j])
            if q != 0:
                for idx in range(len(b[k])):
                    b[k][idx] -= q * b[j][idx]
                # Update mu values incrementally.
                for idx in range(j + 1):
                    mu[k][idx] -= q * mu[j][idx]
                mu[k][j] -= q  # was -= q * mu[j][j] but mu[j][j] = 1 by convention

        # Recompute b_star[k] and the relevant mu row after size reduction.
        b_star, mu = _gs_orthogonalize(b)

        if _norm_sq(b_star[k]) >= (_DELTA - mu[k][k - 1] ** 2) * _norm_sq(b_star[k - 1]):
            k += 1
        else:
            b[k], b[k - 1] = b[k - 1], b[k]
            b_star, mu = _gs_orthogonalize(b)
            k = max(k - 1, 1)

    return b


def round_half_to_even(x: Fraction) -> int:
    """Round ``x`` to nearest int, ties to even (banker's rounding).

    LLL needs a stable rounding rule; banker's rounding avoids the
    asymmetric bias of "round half up" on adversarially-chosen inputs.
    Uses Python's floor division (``//``) which correctly handles
    negatives toward minus infinity, e.g. ``-3 // 2 == -2``.
    """
    floor = x.numerator // x.denominator
    frac = x - floor  # always in [0, 1)
    if frac < Fraction(1, 2):
        return floor
    if frac > Fraction(1, 2):
        return floor + 1
    # Exactly half — round to even.
    return floor if floor % 2 == 0 else floor + 1


__all__ = ["lll_reduce", "round_half_to_even"]
