"""Unit tests for ``prng.derive`` — Trezor / iancoleman.io reference vectors."""

from __future__ import annotations

import hashlib

import pytest
from coincurve import PrivateKey

from wallet_self_audit.prng.bip39 import mnemonic_to_entropy
from wallet_self_audit.prng.derive import (
    address_from_pubkey,
    addresses_from_privkey,
    first_addresses,
)

# (mnemonic, expected p2pkh, expected p2sh-p2wpkh, expected p2wpkh)
# Sourced from Trezor official BIP-39 test vectors + iancoleman.io derivation
# for empty passphrase, m/<purpose>'/0'/0'/0/0.
_VECTORS: list[tuple[str, str, str, str]] = [
    (
        "abandon abandon abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon about",
        "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA",
        "37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf",
        "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
    ),
]


@pytest.mark.parametrize(("mnemonic", "p2pkh", "p2sh", "p2wpkh"), _VECTORS)
def test_first_addresses_match_trezor(
    mnemonic: str, p2pkh: str, p2sh: str, p2wpkh: str
) -> None:
    entropy = mnemonic_to_entropy(mnemonic)
    addrs = first_addresses(entropy)
    assert addrs.p2pkh_bip44 == p2pkh
    assert addrs.p2sh_p2wpkh_bip49 == p2sh
    assert addrs.p2wpkh_bip84 == p2wpkh


def test_brainwallet_password_derivation() -> None:
    """sha256('password') must produce the well-known compromised brainwallet."""
    pk = hashlib.sha256(b"password").digest()
    addrs = addresses_from_privkey(pk)
    # This address is the canonical "brainwallet drained on first deposit"
    # example. It is publicly documented; safe to put in a test.
    assert addrs.p2pkh_bip44 == "16qVRutZ7rZuPx7NMtapvZorWYjyaME2Ue"


def test_addresses_from_privkey_length_check() -> None:
    with pytest.raises(ValueError, match="32 bytes"):
        addresses_from_privkey(b"\x01" * 31)


def test_address_from_pubkey_unknown_kind() -> None:
    pub = PrivateKey(b"\x01" * 32).public_key.format(compressed=True)
    with pytest.raises(ValueError, match="unknown address kind"):
        address_from_pubkey(pub, "p2tr")
