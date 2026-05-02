"""Unit tests for ``prng.bip39``."""

from __future__ import annotations

import os

import pytest

from wallet_self_audit.prng.bip39 import (
    InvalidMnemonic,
    entropy_to_mnemonic,
    expected_entropy_bytes,
    mnemonic_to_entropy,
)

# Canonical Trezor BIP-39 test vectors (subset).
_TREZOR_VECTORS: list[tuple[str, str]] = [
    (
        "00000000000000000000000000000000",
        "abandon abandon abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon about",
    ),
    (
        "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
        "legal winner thank year wave sausage worth useful legal winner "
        "thank yellow",
    ),
    (
        "80808080808080808080808080808080",
        "letter advice cage absurd amount doctor acoustic avoid letter "
        "advice cage above",
    ),
    (
        "ffffffffffffffffffffffffffffffff",
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
    ),
    (
        "0000000000000000000000000000000000000000000000000000000000000000",
        "abandon abandon abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon abandon abandon art",
    ),
]


@pytest.mark.parametrize(("entropy_hex", "mnemonic"), _TREZOR_VECTORS)
def test_trezor_vectors_roundtrip(entropy_hex: str, mnemonic: str) -> None:
    entropy = bytes.fromhex(entropy_hex)
    assert entropy_to_mnemonic(entropy) == mnemonic
    assert mnemonic_to_entropy(mnemonic) == entropy


def test_random_entropy_roundtrip() -> None:
    for length in (16, 20, 24, 28, 32):
        for _ in range(20):
            ent = os.urandom(length)
            m = entropy_to_mnemonic(ent)
            assert mnemonic_to_entropy(m) == ent


def test_invalid_word_count_raises() -> None:
    with pytest.raises(InvalidMnemonic, match="unsupported word count"):
        mnemonic_to_entropy("abandon abandon")


def test_unknown_word_raises() -> None:
    with pytest.raises(InvalidMnemonic, match="not in BIP-39 wordlist"):
        # 'notaword' is not in the BIP-39 wordlist.
        mnemonic_to_entropy(
            "notaword abandon abandon abandon abandon abandon abandon abandon "
            "abandon abandon abandon about"
        )


def test_bad_checksum_raises() -> None:
    # 12x 'abandon' is one syllable off — checksum doesn't match.
    with pytest.raises(InvalidMnemonic, match="checksum mismatch"):
        mnemonic_to_entropy(
            "abandon abandon abandon abandon abandon abandon abandon abandon "
            "abandon abandon abandon abandon"
        )


def test_invalid_entropy_length_raises() -> None:
    with pytest.raises(InvalidMnemonic, match="must be 16/20/24/28/32"):
        entropy_to_mnemonic(b"\x00" * 17)


def test_expected_entropy_bytes_table() -> None:
    assert expected_entropy_bytes(12) == 16
    assert expected_entropy_bytes(15) == 20
    assert expected_entropy_bytes(18) == 24
    assert expected_entropy_bytes(21) == 28
    assert expected_entropy_bytes(24) == 32


def test_expected_entropy_bytes_unknown() -> None:
    with pytest.raises(InvalidMnemonic):
        expected_entropy_bytes(13)


def test_mnemonic_normalisation_whitespace_and_case() -> None:
    """Leading/trailing whitespace and mixed case should be tolerated."""
    canonical = (
        "abandon abandon abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon about"
    )
    messy = "  Abandon  ABANDON " + " ".join(canonical.split()[2:]) + "  "
    assert mnemonic_to_entropy(messy) == bytes(16)
