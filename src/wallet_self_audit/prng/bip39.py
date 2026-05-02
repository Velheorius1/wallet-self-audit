"""BIP-39 entropy ↔ mnemonic conversion — fast pure reverse, no PBKDF2.

The Milk Sad and Randstorm scanners need to compare **entropy bytes**, not
seeds, because PBKDF2-HMAC-SHA512 (2048 rounds) costs ~4 ms per candidate on
M-series and would gate the whole audit at ~250 candidates/sec.

By comparing 16-byte entropy directly we skip PBKDF2 entirely. A user enters
their mnemonic once, we convert it to entropy via the wordlist, and every
candidate in the brute-force loop produces 16 bytes that we just compare.

This module is independent of network / coincurve so it is safe to import in
worker subprocesses.
"""

from __future__ import annotations

import hashlib
from typing import Final

from mnemonic import Mnemonic

# We support 12-word (128-bit) and 24-word (256-bit) English mnemonics.
# Milk Sad / Randstorm only ever produced 12-word, but we want the wrapper
# to be honest about which lengths it accepts.
_SUPPORTED_WORD_COUNTS: Final[frozenset[int]] = frozenset({12, 15, 18, 21, 24})

# Map word count → entropy length in bytes.
_ENTROPY_BYTES_BY_WORD_COUNT: Final[dict[int, int]] = {
    12: 16,
    15: 20,
    18: 24,
    21: 28,
    24: 32,
}


class InvalidMnemonic(ValueError):
    """Raised when a mnemonic is structurally invalid (length, checksum)."""


def _wordlist() -> list[str]:
    """Return the English BIP-39 wordlist (cached by ``Mnemonic``)."""
    # Mnemonic("english").wordlist is a list[str] of length 2048.
    return Mnemonic("english").wordlist


def mnemonic_to_entropy(mnemonic: str) -> bytes:
    """Convert a BIP-39 mnemonic to its raw entropy bytes.

    The mnemonic is normalised: leading/trailing whitespace stripped, internal
    whitespace collapsed to single spaces, lowercased.

    Args:
        mnemonic: Whitespace-separated English BIP-39 words.

    Returns:
        Entropy bytes (16, 20, 24, 28, or 32 depending on word count).

    Raises:
        InvalidMnemonic: If the word count is unsupported, a word is not in
            the BIP-39 list, or the checksum fails.
    """
    words = mnemonic.lower().split()
    if len(words) not in _SUPPORTED_WORD_COUNTS:
        raise InvalidMnemonic(
            f"unsupported word count {len(words)}; expected one of {sorted(_SUPPORTED_WORD_COUNTS)}"
        )

    wordlist = _wordlist()
    word_to_index = {w: i for i, w in enumerate(wordlist)}

    indices: list[int] = []
    for w in words:
        if w not in word_to_index:
            raise InvalidMnemonic(f"word not in BIP-39 wordlist: {w!r}")
        indices.append(word_to_index[w])

    # Pack 11-bit indices into a bitstream. Total bits = 11 * word_count.
    # Of those: ENT entropy bits + CS checksum bits, where CS = ENT/32.
    total_bits = 11 * len(words)
    ent_bits = total_bits * 32 // 33  # ENT/CS = 32/1 ratio
    cs_bits = total_bits - ent_bits
    ent_bytes = ent_bits // 8

    bits = 0
    for idx in indices:
        bits = (bits << 11) | idx

    checksum = bits & ((1 << cs_bits) - 1)
    entropy_int = bits >> cs_bits
    entropy = entropy_int.to_bytes(ent_bytes, "big")

    expected_checksum = hashlib.sha256(entropy).digest()[0] >> (8 - cs_bits)
    if checksum != expected_checksum:
        raise InvalidMnemonic("checksum mismatch")

    return entropy


def entropy_to_mnemonic(entropy: bytes) -> str:
    """Convert raw entropy bytes to a BIP-39 English mnemonic.

    Inverse of :func:`mnemonic_to_entropy`.

    Args:
        entropy: 16, 20, 24, 28, or 32 bytes.

    Returns:
        Whitespace-separated English BIP-39 mnemonic.

    Raises:
        InvalidMnemonic: If the entropy length is unsupported.
    """
    if len(entropy) not in (16, 20, 24, 28, 32):
        raise InvalidMnemonic(
            f"entropy must be 16/20/24/28/32 bytes, got {len(entropy)}"
        )

    ent_bits = len(entropy) * 8
    cs_bits = ent_bits // 32
    word_count = (ent_bits + cs_bits) // 11

    checksum = hashlib.sha256(entropy).digest()[0] >> (8 - cs_bits)
    bits = (int.from_bytes(entropy, "big") << cs_bits) | checksum

    wordlist = _wordlist()
    words: list[str] = []
    for i in range(word_count - 1, -1, -1):
        idx = (bits >> (11 * i)) & 0x7FF
        words.append(wordlist[idx])
    return " ".join(words)


def expected_entropy_bytes(word_count: int) -> int:
    """Return the number of entropy bytes for a given mnemonic word count.

    Raises:
        InvalidMnemonic: If the word count is unsupported.
    """
    if word_count not in _ENTROPY_BYTES_BY_WORD_COUNT:
        raise InvalidMnemonic(
            f"unsupported word count {word_count}; expected one of {sorted(_SUPPORTED_WORD_COUNTS)}"
        )
    return _ENTROPY_BYTES_BY_WORD_COUNT[word_count]
