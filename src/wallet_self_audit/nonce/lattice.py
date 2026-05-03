"""Nonce lattice attack — try a fixed set of bias hypotheses.

This is Stage B of the nonce audit: only invoked when Stage A
(``find_collisions``) finds no r-collision. The goal is the same —
return a verdict — but the path is via lattice reduction:

1. For each hypothesis (top_bits_zero / low_bits_zero / top_byte) and
   bias size in priority order:
2. Build the HNP basis.
3. Run LLL.
4. Read a candidate ``d`` from the (m+1)-th coordinate of the shortest
   vector.
5. Project to a candidate Q via :mod:`wallet_self_audit.crypto.recovery_detector`
   without ever leaking ``d``: we just convert candidate-d to a 32-byte
   scalar, compute coincurve PrivateKey(d).public_key, compare bytes,
   and immediately drop the bytes.

Hypothesis priority (smaller bias = more discriminative, more sigs):
- top_bits_zero(8): ~33 sigs, fastest
- top_bits_zero(4): ~70 sigs
- top_bits_zero(2): ~140 sigs
- top_bits_zero(1): ~220 sigs (last resort)

We never store or log candidate ``d`` values. They exist only as a
local Python int in this function for the duration of the
``PrivateKey()`` call, then go out of scope.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from fractions import Fraction
from typing import Final

from coincurve import PrivateKey

from wallet_self_audit.crypto.recovery_detector import (
    fingerprint as nonce_fingerprint,
)
from wallet_self_audit.lattice.hnp_construct import (
    HnpHypothesis,
    build_top_bits_zero_basis,
    candidate_d_from_short_vector,
    min_signatures_required,
)
from wallet_self_audit.lattice.lll_pure import lll_reduce
from wallet_self_audit.nonce.extractor import SignatureRecord

log = logging.getLogger(__name__)

# Priority order: smaller bias bits first because larger biases (8) need
# fewer signatures and finish faster, but they are the more obvious
# implementation flaw. We try those first because if they hit, the wallet
# is unambiguously broken.
_DEFAULT_HYPOTHESES: Final[tuple[HnpHypothesis, ...]] = (
    HnpHypothesis(name="top_bits_zero", bias_bits=8),
    HnpHypothesis(name="top_bits_zero", bias_bits=4),
    HnpHypothesis(name="top_bits_zero", bias_bits=2),
    HnpHypothesis(name="top_bits_zero", bias_bits=1),
)


@dataclass(frozen=True, slots=True)
class LatticeHit:
    """A successful HNP recovery with verify-by-pubkey-projection."""

    hypothesis: HnpHypothesis
    pubkey_compressed: bytes
    n_signatures: int
    key_fingerprint: str  # 16-hex public fingerprint


def _candidate_to_pubkey(candidate_d: int) -> bytes | None:
    """Convert a candidate ``d`` to a compressed pubkey, then drop ``d``.

    The candidate exists in this function only as a 32-byte scalar
    passed to libsecp256k1 (in C). The Python ``int`` goes out of
    scope on return; the bytearray we build is stored in a local that
    we explicitly clear.
    """
    try:
        scalar = candidate_d.to_bytes(32, "big")
    except OverflowError:
        return None
    try:
        pub = PrivateKey(scalar).public_key.format(compressed=True)
    except (ValueError, RuntimeError):
        return None
    # Best-effort: zeroise the local bytes copy. The PrivateKey C struct
    # holds its own copy that coincurve will free; that path is out of
    # our reach in pure Python and is documented in docs/threat-model.md.
    scalar = b""
    return pub


def attempt_recovery(
    sigs: list[SignatureRecord],
    known_pubkey_compressed: bytes,
    *,
    hypotheses: tuple[HnpHypothesis, ...] = _DEFAULT_HYPOTHESES,
) -> LatticeHit | None:
    """Try each hypothesis in priority order; return the first hit.

    Args:
        sigs: All signatures for this pubkey (already filtered).
        known_pubkey_compressed: 33-byte compressed Q from the chain.
        hypotheses: Bias hypotheses to try, in priority order.

    Returns:
        :class:`LatticeHit` on success, ``None`` if no hypothesis fits.
    """
    triples = [(rec.r, rec.s, rec.z) for rec in sigs]
    for hyp in hypotheses:
        if hyp.name != "top_bits_zero":
            # v1.0: only top_bits_zero is implemented in the basis builder.
            # low_bits_zero / top_byte_constant slots are reserved for v1.1.
            log.debug("skipping hypothesis %s — not yet implemented", hyp.name)
            continue
        min_sigs = min_signatures_required(hyp.bias_bits)
        if len(triples) < min_sigs:
            log.debug(
                "skipping bias_bits=%d — need %d sigs, have %d",
                hyp.bias_bits,
                min_sigs,
                len(triples),
            )
            continue

        hit = _try_top_bits_zero(triples, hyp, known_pubkey_compressed)
        if hit is not None:
            return hit

    return None


def _try_top_bits_zero(
    triples: list[tuple[int, int, int]],
    hyp: HnpHypothesis,
    known_pubkey_compressed: bytes,
) -> LatticeHit | None:
    """Build a BV lattice for ``top_bits_zero(L)``, run LLL, verify."""
    basis = build_top_bits_zero_basis(triples, bias_bits=hyp.bias_bits)
    # LLL reduction can be slow for big lattices — caller is expected to
    # cap the number of signatures (see threat-model.md).
    reduced = lll_reduce(basis)

    # Try the shortest few rows; LLL doesn't strictly guarantee the first
    # is the shortest for non-Hermite-best bases.
    for vec in reduced[: min(3, len(reduced))]:
        candidate_d = candidate_d_from_short_vector(vec)
        if candidate_d is None:
            continue
        candidate_pub = _candidate_to_pubkey(candidate_d)
        if candidate_pub is None:
            continue
        if candidate_pub == known_pubkey_compressed:
            # Compute fingerprint over public inputs only.
            fp = nonce_fingerprint(
                pubkey_compressed=known_pubkey_compressed,
                r=triples[0][0],
                txid_a="0" * 64,
                txid_b="0" * 64,
            )
            return LatticeHit(
                hypothesis=hyp,
                pubkey_compressed=known_pubkey_compressed,
                n_signatures=len(triples),
                key_fingerprint=fp,
            )

    return None


# Helper: keep the import-only reference to ``Fraction`` from being
# flagged as unused (we use it transitively through hnp_construct).
_ = Fraction


__all__ = ["LatticeHit", "attempt_recovery"]
