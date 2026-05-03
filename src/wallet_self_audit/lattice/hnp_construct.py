"""Hidden Number Problem (HNP) basis construction for biased ECDSA nonces.

Given a list of ECDSA signatures ``(r_i, s_i, z_i)`` produced with the
same private key ``d`` and per-signature nonces ``k_i`` that share a
known structural bias (e.g. the top L bits are zero), the relation::

    s_i * k_i  ≡  z_i + r_i * d   (mod n)

defines a system that can be solved as an instance of the Hidden Number
Problem. Following Boneh-Venkatesan (1996) and Howgrave-Graham-Smart
(2001), we encode this as a lattice and use LLL to find a short vector
that reveals ``d`` to within the bias precision.

The "verify-by-pubkey-projection" oracle in
``crypto.recovery_detector`` then promotes a candidate ``d`` to a
verdict — but only via a public-key-side projection. We never store
the candidate ``d`` long enough to leak it.

Hypotheses we support in v1.0:
- ``top_bits_zero(L)``: the top ``L`` bits of every nonce are zero.
- ``low_bits_zero(L)``: the low ``L`` bits of every nonce are zero
  (Howgrave-Graham construction).
- ``top_byte_constant``: the top byte is the same constant across all
  signatures (histogram-based detection picks the constant).

Required signature counts (hard threshold below which we refuse to
even attempt LLL):

============  ========
Bias bits L   Min sigs
============  ========
1             220
2             140
4             70
8             33
============  ========
"""

from __future__ import annotations

from dataclasses import dataclass
from fractions import Fraction
from typing import Final, Literal

# secp256k1 curve order.
SECP256K1_N: Final[int] = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


HypothesisName = Literal["top_bits_zero", "low_bits_zero", "top_byte_constant"]


@dataclass(frozen=True, slots=True)
class HnpHypothesis:
    """One bias hypothesis the lattice attack will try."""

    name: HypothesisName
    bias_bits: int
    # ``constant_byte`` is only meaningful for ``top_byte_constant``.
    constant_byte: int = 0


# Required signature counts per bias size — below these, do not even try.
_MIN_SIGS_BY_BIAS: Final[dict[int, int]] = {1: 220, 2: 140, 4: 70, 8: 33}


def min_signatures_required(bias_bits: int) -> int:
    """Return the minimum number of signatures needed for the given bias.

    Smaller bias → bigger lattice → more signatures. The thresholds are
    conservative empirical numbers from public HNP literature.
    """
    if bias_bits <= 0:
        raise ValueError("bias_bits must be >= 1")
    if bias_bits >= 8:
        return _MIN_SIGS_BY_BIAS[8]
    # Find the smallest threshold (l_thresh) >= bias_bits.
    for l_thresh in sorted(_MIN_SIGS_BY_BIAS):
        if bias_bits <= l_thresh:
            return _MIN_SIGS_BY_BIAS[l_thresh]
    return _MIN_SIGS_BY_BIAS[max(_MIN_SIGS_BY_BIAS)]


# ---------------------------------------------------------------------------
# Top-bits-zero construction (Boneh-Venkatesan).
# ---------------------------------------------------------------------------
def build_top_bits_zero_basis(
    sigs: list[tuple[int, int, int]],
    *,
    bias_bits: int,
    n: int = SECP256K1_N,
) -> list[list[Fraction]]:
    """Build the BV lattice basis for ``top_bits_zero(L)``.

    The classical BV basis with m signatures is an (m+2) x (m+2) matrix:

        [ 2^L · n,   0,        ...,       0,      0,        0 ]
        [    0,   2^L · n,     ...,       0,      0,        0 ]
        [   ...,    ...,       ...,      ...,    ...,      ... ]
        [    0,      0,        ...,   2^L · n,    0,        0 ]
        [   c_1,    c_2,       ...,    c_m,       1,        0 ]
        [   d_1,    d_2,       ...,    d_m,       0,    2^L · n / 2 ]

    where c_i = (2^L · s_i^-1 · r_i) mod n and d_i = (2^L · s_i^-1 · z_i) mod n.
    A short vector in this lattice has its (m+1)-th entry close to ``d``.

    For implementation simplicity (and given ``fractions.Fraction``
    handles arbitrary precision), we use this exact construction with
    multipliers chosen so that all entries are integers.

    Args:
        sigs: List of ``(r_i, s_i, z_i)`` triples (all mod n).
        bias_bits: How many high bits of each nonce are zero.
        n: Curve order. Defaults to secp256k1.

    Returns:
        Basis as a list of row-vectors with ``Fraction`` entries.
    """
    if not sigs:
        raise ValueError("need at least one signature")
    if bias_bits <= 0:
        raise ValueError("bias_bits must be >= 1")
    m = len(sigs)
    pow_l = 1 << bias_bits
    basis: list[list[Fraction]] = []

    # Top m rows: 2^L · n on the diagonal, zeros elsewhere.
    for i in range(m):
        row = [Fraction(0)] * (m + 2)
        row[i] = Fraction(pow_l * n)
        basis.append(row)

    # Row m: ((2^L · s_i^-1 · r_i) mod n)_i, then 1, then 0.
    c_row: list[Fraction] = []
    d_row: list[Fraction] = []
    for r_i, s_i, z_i in sigs:
        s_inv = pow(s_i, -1, n)
        c_i = (pow_l * s_inv * r_i) % n
        d_i = (pow_l * s_inv * z_i) % n
        c_row.append(Fraction(c_i))
        d_row.append(Fraction(d_i))

    c_row.extend([Fraction(1), Fraction(0)])
    d_row.extend([Fraction(0), Fraction(pow_l) * Fraction(n) / Fraction(2)])
    basis.append(c_row)
    basis.append(d_row)

    return basis


def candidate_d_from_short_vector(
    vec: list[Fraction],
    *,
    n: int = SECP256K1_N,
) -> int | None:
    """Extract a ``d`` candidate from a short vector returned by LLL.

    The short vector is expected to lie in the same lattice as the BV
    basis; its (m+1)-th coordinate is the recovered ``d``-component
    (modulo n). If the coordinate is non-integer or out-of-range, this
    returns ``None``.

    NOTE: returning a Python ``int`` here is the *only* place a
    ``d``-shaped value briefly exists in our process. It is consumed
    immediately by the recovery-detector projection (which converts to
    bytes and compares pubkeys), then dropped. Callers MUST NOT log,
    store, or pickle the return value.
    """
    if len(vec) < 2:
        return None
    coord = vec[-2]
    if coord.denominator != 1:
        return None
    candidate = int(coord) % n
    if not 1 <= candidate < n:
        return None
    return candidate


__all__ = [
    "SECP256K1_N",
    "HnpHypothesis",
    "HypothesisName",
    "build_top_bits_zero_basis",
    "candidate_d_from_short_vector",
    "min_signatures_required",
]
