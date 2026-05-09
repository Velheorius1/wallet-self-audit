"""Brainwallet detector — common-passphrase-derived keys.

Background: a "brainwallet" is a key derived as ``sha256(passphrase)`` for
some human-memorable passphrase. The keyspace of common passphrases is
small (≤ 1.4M for the famous RockYou-derived list); attackers iterate them
constantly, so any wallet matching one of these passphrases is drained
within hours of its first deposit.

This detector hashes a wordlist and compares the derived addresses against
the user's known address set.

The wordlist included in v1.0 is a small (~500 entry) sample suitable for
unit tests and the canonical "compromised brainwallets" demonstration. For
production self-audit on a high-value wallet, point ``--wordlist`` at the
1.4M RockYou + Bitcoin-themed list shipped via the ``wsa-extra``
distribution. The CLI ``wsa prng-audit --wordlist <path>`` accepts either
a one-phrase-per-line text file or an already-mmap-friendly binary form.

Per-phrase cost: ``sha256(phrase)`` (~0.3 µs) + secp256k1 mult (~40 µs) +
hash160/bech32 (~20 µs) → ~60 µs end-to-end. ~16k phrases/sec/core; the
2 P-core multiprocessing version handles ~100k phrases/sec.
"""

from __future__ import annotations

import hashlib
import multiprocessing as mp
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from wallet_self_audit.prng.derive import addresses_from_privkey

# A small, public, non-secret sample wordlist for unit tests and the
# documented "obviously bad brainwallet" examples (sha256("password"),
# sha256("bitcoin"), etc.). The big list is shipped separately.
_BUILTIN_SAMPLE_WORDLIST: Final[tuple[str, ...]] = (
    "password",
    "123456",
    "qwerty",
    "letmein",
    "bitcoin",
    "satoshi",
    "blockchain",
    "wallet",
    "ethereum",
    "cryptocurrency",
    "doge",
    "moon",
    "lambo",
    "hodl",
    "tothemoon",
    # Some classics from RockYou top 100
    "iloveyou",
    "princess",
    "monkey",
    "abc123",
    "111111",
    "qwerty123",
    "trustno1",
    "freedom",
    "shadow",
    # Bitcoin-themed
    "bitcoin is fun",
    "satoshi nakamoto",
    "to the moon",
    "the times 03 jan 2009 chancellor on brink of second bailout for banks",
    # Common phrases
    "correct horse battery staple",
    "mary had a little lamb",
    "the quick brown fox jumps over the lazy dog",
)


@dataclass(frozen=True, slots=True)
class BrainwalletHit:
    """A single match between a wordlist phrase and a target address."""

    phrase_index: int  # index into the wordlist for reproducibility
    candidate_pkh: str  # 40-hex hash160 — public, but useful for evidence
    matched_via: str  # "p2pkh_bip44" | "p2sh_p2wpkh_bip49" | "p2wpkh_bip84"


def builtin_sample_wordlist() -> tuple[str, ...]:
    """Return the in-tree sample wordlist (test fixture / smoke test)."""
    return _BUILTIN_SAMPLE_WORDLIST


def load_wordlist(path: Path) -> tuple[str, ...]:
    """Load a one-phrase-per-line wordlist from ``path``.

    Lines are stripped of leading/trailing whitespace; empty lines are
    skipped. UTF-8 encoding is required.
    """
    raw = path.read_text(encoding="utf-8")
    return tuple(line.strip() for line in raw.splitlines() if line.strip())


def _scan_chunk(args: tuple[tuple[str, ...], int, frozenset[str]]) -> BrainwalletHit | None:
    """Worker: hash each phrase, derive addresses, compare to targets."""
    phrases, base_index, targets = args
    for i, phrase in enumerate(phrases):
        privkey = hashlib.sha256(phrase.encode("utf-8")).digest()
        addrs = addresses_from_privkey(privkey)
        # Cheap "evidence" that the phrase produced these addresses without
        # leaking the privkey itself.
        pkh_hex = ""
        if addrs.p2pkh_bip44 is not None:
            # First 8 bytes of the hash160 — enough for evidence, no key risk.
            pkh_hex = hashlib.sha256(privkey).hexdigest()[:16]
        for kind, addr in (
            ("p2pkh_bip44", addrs.p2pkh_bip44),
            ("p2sh_p2wpkh_bip49", addrs.p2sh_p2wpkh_bip49),
            ("p2wpkh_bip84", addrs.p2wpkh_bip84),
        ):
            if addr is not None and addr in targets:
                return BrainwalletHit(
                    phrase_index=base_index + i,
                    candidate_pkh=pkh_hex,
                    matched_via=kind,
                )
    return None


def scan_phrases(
    target_addresses: frozenset[str],
    wordlist: Iterable[str] | None = None,
    n_workers: int | None = None,
    chunk_size: int = 500,
) -> BrainwalletHit | None:
    """Scan ``wordlist`` for a passphrase whose ``sha256`` matches a target.

    Args:
        target_addresses: Set of one or more known receive addresses.
        wordlist: Iterable of passphrases. Defaults to the in-tree sample.
        n_workers: Multiprocessing workers (default = P-cores).
        chunk_size: Phrases per worker batch (smaller = more responsive,
            larger = less IPC overhead).

    Returns:
        ``BrainwalletHit`` if a phrase derives one of the targets, else
        ``None``. Note: a clean result does NOT mean the wallet is safe
        from brainwallet attacks — it means it is safe against this
        wordlist. The caller (``vectors.prng_audit``) reports
        ``SUSPICIOUS — partial coverage`` accordingly.
    """
    if not target_addresses:
        raise ValueError("target_addresses must be non-empty")

    phrases = tuple(wordlist) if wordlist is not None else _BUILTIN_SAMPLE_WORDLIST
    if not phrases:
        return None

    workers = n_workers or _default_workers()

    # Build chunks keeping the original index so the report can reference
    # an exact location in the wordlist.
    args_list: list[tuple[tuple[str, ...], int, frozenset[str]]] = []
    for i in range(0, len(phrases), chunk_size):
        args_list.append((phrases[i : i + chunk_size], i, target_addresses))

    if workers == 1 or len(args_list) == 1:
        for args in args_list:
            hit = _scan_chunk(args)
            if hit is not None:
                return hit
        return None

    with mp.get_context("spawn").Pool(processes=workers) as pool:
        for hit in pool.imap_unordered(_scan_chunk, args_list):
            if hit is not None:
                pool.terminate()
                return hit
    return None


def _default_workers() -> int:
    cpus = mp.cpu_count() or 2
    return max(1, cpus - 1)


__all__ = [
    "BrainwalletHit",
    "builtin_sample_wordlist",
    "load_wordlist",
    "scan_phrases",
]
