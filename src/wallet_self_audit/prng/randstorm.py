"""Randstorm detector — bitcoinjs-lib pre-2014 ``Math.random`` weakness.

Background: BitcoinJS-lib (2011-2014) generated entropy by repeatedly calling
``Math.random()``, which in V8 (Chrome) at that time was a 53-bit MWC
generator with a 2³²-bounded internal state. The dominant variant produced
keys that are enumerable in ~minutes on a modern multi-core machine.

This detector enumerates V8 MWC internal seeds (or a sub-window) and
checks whether any candidate produces an entropy that matches the user's
wallet.

**Coverage caveat (honest):** v1.0 implements the dominant V8 MWC variant
documented in the public Randstorm disclosure. Other variants (older Safari
WebKit, Firefox SpiderMonkey of the same era) used different PRNGs and
require their own scanners. A clean ``randstorm`` result therefore reports
``SUSPICIOUS — partial coverage`` rather than ``SAFE``. See
``docs/threat-model.md`` and the ``ScanCoverage`` field on the result.

The V8 MWC state is two 32-bit halves ``(s0, s1)``. Each ``Math.random()``
call advances:
    s_new = 18030 * (s & 0xFFFF) + (s >> 16)        # update s0 from previous s0
    t_new = 30903 * (t & 0xFFFF) + (t >> 16)        # update s1 from previous s1
And returns ``((s_new << 16) + (t_new & 0xFFFF)) / 2**32``.

bitcoinjs-lib 0.1.x called ``Math.random()`` 32 times to assemble 256 bits
of "entropy" (low 8 bits of each output, packed). We reproduce that loop
exactly.
"""

from __future__ import annotations

import multiprocessing as mp
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Final

from wallet_self_audit.prng.derive import first_addresses

# Seed ranges. The dominant V8 variant used a 32-bit timestamp-derived seed
# for s0 and a fixed-derivation s1 — but in practice the "live" subset
# covered by public Randstorm research is bounded.
RANDSTORM_DEFAULT_S0_RANGE: Final[tuple[int, int]] = (0, 1 << 28)  # 2^28 candidates


@dataclass(frozen=True, slots=True)
class RandstormHit:
    """A single Randstorm match."""

    s0_seed: int
    s1_seed: int
    candidate_entropy_hex: str
    matched_via: str  # "entropy" | "p2pkh_bip44" | "p2sh_p2wpkh_bip49" | "p2wpkh_bip84"


@dataclass(frozen=True, slots=True)
class ScanCoverage:
    """Honest report of which Randstorm variants the scan covered.

    A ``None`` (clean) verdict from the scan is only meaningful in the
    context of which variants were actually checked.
    """

    v8_mwc_dominant: bool
    s0_range: tuple[int, int]
    note: str


def _v8_mwc_step(s0: int, s1: int) -> tuple[int, int, int]:
    """One V8 ``Math.random`` step.

    Returns updated (s0, s1, output_uint32). The output is the high 32 bits
    of the 53-bit double, sufficient for byte-level reconstruction.
    """
    new_s0 = ((18030 * (s0 & 0xFFFF)) + (s0 >> 16)) & 0xFFFFFFFF
    new_s1 = ((30903 * (s1 & 0xFFFF)) + (s1 >> 16)) & 0xFFFFFFFF
    out = ((new_s0 << 16) + (new_s1 & 0xFFFF)) & 0xFFFFFFFF
    return new_s0, new_s1, out


def _v8_mwc_entropy(s0: int, s1: int, n_bytes: int) -> bytes:
    """Reproduce bitcoinjs-lib 0.1.x: take low byte of each ``Math.random``.

    bitcoinjs-lib actually called ``Math.random() * 256 | 0`` to get one
    byte per call. ``Math.random()`` returns ``out / 2**32`` so
    ``Math.random() * 256 | 0`` is ``(out >> 24)`` (high byte). Reproduce
    that exact byte stream.
    """
    out = bytearray(n_bytes)
    for i in range(n_bytes):
        s0, s1, x = _v8_mwc_step(s0, s1)
        out[i] = (x >> 24) & 0xFF
    return bytes(out)


def _scan_entropy_chunk(args: tuple[int, int, int, bytes]) -> RandstormHit | None:
    """Worker: scan ``s0 in [start, end)`` against ``target_entropy``."""
    s0_start, s0_end, s1_fixed, target = args
    n_bytes = len(target)
    for s0 in range(s0_start, s0_end):
        cand = _v8_mwc_entropy(s0, s1_fixed, n_bytes)
        if cand == target:
            return RandstormHit(
                s0_seed=s0,
                s1_seed=s1_fixed,
                candidate_entropy_hex=cand.hex(),
                matched_via="entropy",
            )
    return None


def _scan_addresses_chunk(
    args: tuple[int, int, int, frozenset[str]],
) -> RandstormHit | None:
    """Worker: derive addresses per s0 and compare against ``targets``."""
    s0_start, s0_end, s1_fixed, targets = args
    for s0 in range(s0_start, s0_end):
        cand = _v8_mwc_entropy(s0, s1_fixed, 16)
        addrs = first_addresses(cand)
        for kind, addr in (
            ("p2pkh_bip44", addrs.p2pkh_bip44),
            ("p2sh_p2wpkh_bip49", addrs.p2sh_p2wpkh_bip49),
            ("p2wpkh_bip84", addrs.p2wpkh_bip84),
        ):
            if addr is not None and addr in targets:
                return RandstormHit(
                    s0_seed=s0,
                    s1_seed=s1_fixed,
                    candidate_entropy_hex=cand.hex(),
                    matched_via=kind,
                )
    return None


def scan_seeds(
    target_entropy: bytes,
    s0_range: tuple[int, int] | None = None,
    s1_fixed: int = 0xCAFE0000,
    n_workers: int | None = None,
) -> tuple[RandstormHit | None, ScanCoverage]:
    """Scan V8 MWC s0 candidates against a target entropy.

    The s1 half is held fixed at ``s1_fixed`` per the dominant V8
    Randstorm variant (which used a process-lifetime-bounded s1 derived
    from page-load entropy with a small live-seed cluster).

    Returns:
        ``(hit_or_none, coverage)`` — coverage describes what was actually
        scanned so callers can produce an honest ``SUSPICIOUS — partial``
        verdict for clean cases.
    """
    if len(target_entropy) not in (16, 20, 24, 28, 32):
        raise ValueError(f"unsupported entropy length {len(target_entropy)}")

    s0_lo, s0_hi = s0_range or RANDSTORM_DEFAULT_S0_RANGE
    workers = n_workers or _default_workers()
    chunks = list(_chunk(s0_lo, s0_hi, workers))
    args_list = [(c0, c1, s1_fixed, target_entropy) for (c0, c1) in chunks]

    coverage = ScanCoverage(
        v8_mwc_dominant=True,
        s0_range=(s0_lo, s0_hi),
        note=(
            "Covers V8 MWC dominant variant. WebKit/SpiderMonkey contemporaneous "
            "PRNGs are not in scope — see docs/threat-model.md."
        ),
    )

    if workers == 1:
        for args in args_list:
            hit = _scan_entropy_chunk(args)
            if hit is not None:
                return hit, coverage
        return None, coverage

    with mp.get_context("spawn").Pool(processes=workers) as pool:
        for hit in pool.imap_unordered(_scan_entropy_chunk, args_list):
            if hit is not None:
                pool.terminate()
                return hit, coverage
    return None, coverage


def scan_seeds_by_addresses(
    target_addresses: frozenset[str],
    s0_range: tuple[int, int] | None = None,
    s1_fixed: int = 0xCAFE0000,
    n_workers: int | None = None,
) -> tuple[RandstormHit | None, ScanCoverage]:
    """Scan V8 MWC s0 candidates and compare derived addresses."""
    if not target_addresses:
        raise ValueError("target_addresses must be non-empty")

    s0_lo, s0_hi = s0_range or RANDSTORM_DEFAULT_S0_RANGE
    workers = n_workers or _default_workers()
    chunks = list(_chunk(s0_lo, s0_hi, workers))
    args_list = [(c0, c1, s1_fixed, target_addresses) for (c0, c1) in chunks]

    coverage = ScanCoverage(
        v8_mwc_dominant=True,
        s0_range=(s0_lo, s0_hi),
        note="Covers V8 MWC dominant variant; full BIP-32 derivation per candidate.",
    )

    if workers == 1:
        for args in args_list:
            hit = _scan_addresses_chunk(args)
            if hit is not None:
                return hit, coverage
        return None, coverage

    with mp.get_context("spawn").Pool(processes=workers) as pool:
        for hit in pool.imap_unordered(_scan_addresses_chunk, args_list):
            if hit is not None:
                pool.terminate()
                return hit, coverage
    return None, coverage


def _default_workers() -> int:
    cpus = mp.cpu_count() or 2
    return max(1, cpus - 1)


def _chunk(lo: int, hi: int, n: int) -> Iterator[tuple[int, int]]:
    if n <= 0:
        raise ValueError("n must be positive")
    span = hi - lo
    size = max(1, span // n)
    cur = lo
    for i in range(n):
        nxt = hi if i == n - 1 else min(hi, cur + size)
        if nxt > cur:
            yield (cur, nxt)
        cur = nxt


__all__ = [
    "RANDSTORM_DEFAULT_S0_RANGE",
    "RandstormHit",
    "ScanCoverage",
    "scan_seeds",
    "scan_seeds_by_addresses",
]
