"""BIP-32/44/49/84 derivation — entropy → small set of receive addresses.

Goal: take 16-byte entropy, derive the canonical first receive address for
each of the common purposes (44=P2PKH, 49=P2SH-P2WPKH, 84=P2WPKH) and return
the address strings. Comparing addresses is what closes the loop on every
PRNG vector — milk-sad/randstorm/brainwallet candidate produces an entropy,
this module turns it into addresses, the orchestrator compares to user's
known addresses.

We use ``coincurve`` for the elliptic-curve math (libsecp256k1 ARM64 wheel)
and roll our own BIP-32 derivation in pure Python on top — BIP-32 is just
HMAC-SHA512 + a scalar multiply on secp256k1 per step, so no extra dep is
worth it.

This module deliberately implements **only hardened-then-non-hardened**
paths used by the common purposes, not arbitrary derivation. That keeps the
attack surface small and the code reviewable.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from typing import Final

from coincurve import PrivateKey, PublicKey

# secp256k1 curve order.
_SECP256K1_N: Final[int] = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# BIP-39 seed → BIP-32 master key uses HMAC-SHA512 with this key.
_BIP32_MASTER_KEY: Final[bytes] = b"Bitcoin seed"

# Hardened-derivation offset (BIP-32).
_HARDENED: Final[int] = 0x80000000

# Bech32 charset (BIP-173).
_BECH32_CHARSET: Final[str] = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

# Base58 alphabet (Bitcoin variant).
_BASE58_ALPHABET: Final[str] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

# Mainnet prefixes.
_P2PKH_VERSION: Final[int] = 0x00  # BIP-44 — addresses start with '1'
_P2SH_VERSION: Final[int] = 0x05  # BIP-49 — addresses start with '3'
_BECH32_HRP_MAINNET: Final[str] = "bc"  # BIP-84 — addresses start with 'bc1q'


@dataclass(frozen=True, slots=True)
class WalletAddresses:
    """The canonical first receive addresses derived from one entropy.

    The orchestrator can compare the user's known address against any of
    these. ``None`` means derivation failed (rare — can happen if scalar
    multiplication produces an invalid key, probability ~1/2^128).
    """

    p2pkh_bip44: str | None  # m/44'/0'/0'/0/0
    p2sh_p2wpkh_bip49: str | None  # m/49'/0'/0'/0/0
    p2wpkh_bip84: str | None  # m/84'/0'/0'/0/0


def entropy_to_seed(entropy: bytes) -> bytes:
    """BIP-39 PBKDF2 — entropy → 64-byte seed.

    NOTE: most PRNG audit code paths skip this entirely (compare entropy
    bytes directly). We expose it for the rare case where a vector needs
    the full BIP-32 path (e.g. an address-only audit where the user knows
    the address but not the mnemonic).

    Empty passphrase only — that is what the BIP-39 wordlist roundtrip
    convention assumes. If a wallet uses a non-empty passphrase, the
    entropy-direct comparison short-circuit doesn't apply and the user
    needs to enter the passphrase via owner_input.
    """
    # mnemonic-string-to-seed expects the canonical mnemonic; we derive it
    # here for clarity rather than re-implementing the wordlist mapping.
    from wallet_self_audit.prng.bip39 import entropy_to_mnemonic

    mnemonic = entropy_to_mnemonic(entropy)
    salt = b"mnemonic"  # BIP-39 with empty passphrase
    return hashlib.pbkdf2_hmac("sha512", mnemonic.encode("utf-8"), salt, 2048, dklen=64)


def _master_from_seed(seed: bytes) -> tuple[bytes, bytes]:
    """BIP-32: HMAC-SHA512 of the seed with key 'Bitcoin seed'.

    Returns (private_key_bytes, chain_code).
    """
    h = hmac.new(_BIP32_MASTER_KEY, seed, hashlib.sha512).digest()
    return h[:32], h[32:]


def _ckd_priv(parent_priv: bytes, parent_chain: bytes, index: int) -> tuple[bytes, bytes]:
    """BIP-32 child key derivation (private). Supports hardened and non-hardened."""
    if index >= _HARDENED:
        # Hardened: data = 0x00 || parent_priv || index_be
        data = b"\x00" + parent_priv + index.to_bytes(4, "big")
    else:
        # Non-hardened: data = parent_pub_compressed || index_be
        parent_pub = PrivateKey(parent_priv).public_key.format(compressed=True)
        data = parent_pub + index.to_bytes(4, "big")

    h = hmac.new(parent_chain, data, hashlib.sha512).digest()
    il = int.from_bytes(h[:32], "big")
    if il >= _SECP256K1_N:
        # Per BIP-32, this means the derived key is invalid; in practice
        # never happens at probability ~1/2^128.
        raise ValueError("BIP-32 derivation produced il >= n")
    child_priv_int = (il + int.from_bytes(parent_priv, "big")) % _SECP256K1_N
    if child_priv_int == 0:
        raise ValueError("BIP-32 derivation produced zero key")
    return child_priv_int.to_bytes(32, "big"), h[32:]


def _derive_path(seed: bytes, path: tuple[int, ...]) -> bytes:
    """Walk ``path`` from the master and return the leaf private-key bytes."""
    priv, chain = _master_from_seed(seed)
    for index in path:
        priv, chain = _ckd_priv(priv, chain, index)
    return priv


def _hash160(data: bytes) -> bytes:
    """RIPEMD-160 of SHA-256 — Bitcoin's canonical short hash."""
    return hashlib.new("ripemd160", hashlib.sha256(data).digest()).digest()


def _double_sha256(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def _base58_encode(data: bytes) -> str:
    """Base58 encoding (Bitcoin alphabet)."""
    n = int.from_bytes(data, "big")
    out: list[str] = []
    while n > 0:
        n, rem = divmod(n, 58)
        out.append(_BASE58_ALPHABET[rem])
    # Leading zero bytes → leading '1' chars.
    pad = 0
    for b in data:
        if b == 0:
            pad += 1
        else:
            break
    return "1" * pad + "".join(reversed(out))


def _base58check_encode(version: int, payload: bytes) -> str:
    """Add version byte + 4-byte checksum, then Base58."""
    raw = bytes([version]) + payload
    checksum = _double_sha256(raw)[:4]
    return _base58_encode(raw + checksum)


def _bech32_polymod(values: list[int]) -> int:
    """BIP-173 polymod."""
    gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i in range(5):
            chk ^= gen[i] if ((b >> i) & 1) else 0
    return chk


def _bech32_hrp_expand(hrp: str) -> list[int]:
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def _bech32_create_checksum(hrp: str, data: list[int], spec_const: int) -> list[int]:
    values = [*_bech32_hrp_expand(hrp), *data]
    polymod = _bech32_polymod([*values, 0, 0, 0, 0, 0, 0]) ^ spec_const
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]


def _convertbits(data: bytes, frombits: int, tobits: int, pad: bool) -> list[int]:
    acc = 0
    bits = 0
    ret: list[int] = []
    maxv = (1 << tobits) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            raise ValueError("invalid value for convertbits")
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad and bits:
        ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        raise ValueError("invalid padding in convertbits")
    return ret


def _segwit_encode(hrp: str, witver: int, witprog: bytes) -> str:
    """BIP-173 (bech32, witver=0) / BIP-350 (bech32m, witver>0)."""
    # P2WPKH uses witver=0 → bech32 (const 1).
    spec_const = 1 if witver == 0 else 0x2BC830A3
    data = [witver, *_convertbits(witprog, 8, 5, True)]
    checksum = _bech32_create_checksum(hrp, data, spec_const)
    combined = [*data, *checksum]
    return hrp + "1" + "".join(_BECH32_CHARSET[d] for d in combined)


# ---------------------------------------------------------------------------
# Public address derivation
# ---------------------------------------------------------------------------
def _derive_pubkey_at_path(seed: bytes, path: tuple[int, ...]) -> bytes:
    """Derive compressed public key at ``path`` (walking from master)."""
    priv = _derive_path(seed, path)
    return PrivateKey(priv).public_key.format(compressed=True)


def _p2pkh_address(pubkey_compressed: bytes) -> str:
    """P2PKH (BIP-44) — base58check(0x00 || hash160(pubkey))."""
    return _base58check_encode(_P2PKH_VERSION, _hash160(pubkey_compressed))


def _p2sh_p2wpkh_address(pubkey_compressed: bytes) -> str:
    """P2SH-wrapped P2WPKH (BIP-49) — base58check(0x05 || hash160(0x0014 || h160(pk)))."""
    h160 = _hash160(pubkey_compressed)
    redeem_script = b"\x00\x14" + h160  # OP_0 OP_PUSHBYTES_20 <h160>
    return _base58check_encode(_P2SH_VERSION, _hash160(redeem_script))


def _p2wpkh_address(pubkey_compressed: bytes) -> str:
    """Native P2WPKH (BIP-84) — bech32(bc, witver=0, hash160(pubkey))."""
    return _segwit_encode(_BECH32_HRP_MAINNET, 0, _hash160(pubkey_compressed))


_BIP44_FIRST_RECEIVE: Final[tuple[int, ...]] = (
    _HARDENED | 44,  # purpose
    _HARDENED | 0,  # coin_type = bitcoin
    _HARDENED | 0,  # account
    0,  # external (receive) chain
    0,  # first index
)
_BIP49_FIRST_RECEIVE: Final[tuple[int, ...]] = (
    _HARDENED | 49,
    _HARDENED | 0,
    _HARDENED | 0,
    0,
    0,
)
_BIP84_FIRST_RECEIVE: Final[tuple[int, ...]] = (
    _HARDENED | 84,
    _HARDENED | 0,
    _HARDENED | 0,
    0,
    0,
)


def first_addresses(entropy: bytes) -> WalletAddresses:
    """Derive the canonical first receive address for purposes 44/49/84.

    Args:
        entropy: 16/20/24/28/32 byte BIP-39 entropy.

    Returns:
        A ``WalletAddresses`` with one address per common purpose.

    Edge cases (each returned as ``None`` for that purpose):
        - BIP-32 derivation produces ``il >= n`` (P~1/2^128).
        - secp256k1 multiplication would yield identity (P~1/2^128).
    """
    seed = entropy_to_seed(entropy)

    p2pkh: str | None
    p2sh: str | None
    p2wpkh: str | None
    try:
        p2pkh = _p2pkh_address(_derive_pubkey_at_path(seed, _BIP44_FIRST_RECEIVE))
    except (ValueError, RuntimeError):  # pragma: no cover
        p2pkh = None
    try:
        p2sh = _p2sh_p2wpkh_address(_derive_pubkey_at_path(seed, _BIP49_FIRST_RECEIVE))
    except (ValueError, RuntimeError):  # pragma: no cover
        p2sh = None
    try:
        p2wpkh = _p2wpkh_address(_derive_pubkey_at_path(seed, _BIP84_FIRST_RECEIVE))
    except (ValueError, RuntimeError):  # pragma: no cover
        p2wpkh = None

    return WalletAddresses(
        p2pkh_bip44=p2pkh,
        p2sh_p2wpkh_bip49=p2sh,
        p2wpkh_bip84=p2wpkh,
    )


def address_from_pubkey(pubkey_compressed: bytes, kind: str) -> str:
    """Helper: derive an address from a raw compressed pubkey.

    ``kind`` is one of ``"p2pkh"``, ``"p2sh-p2wpkh"``, ``"p2wpkh"``.
    Used by brainwallet (which has a privkey directly, not entropy).
    """
    if kind == "p2pkh":
        return _p2pkh_address(pubkey_compressed)
    if kind == "p2sh-p2wpkh":
        return _p2sh_p2wpkh_address(pubkey_compressed)
    if kind == "p2wpkh":
        return _p2wpkh_address(pubkey_compressed)
    raise ValueError(f"unknown address kind: {kind!r}")


def addresses_from_privkey(privkey: bytes) -> WalletAddresses:
    """Brainwallet shortcut — given a 32-byte privkey, derive all 3 address types.

    ``privkey`` is e.g. ``sha256(passphrase)``. Returns ``None`` for any
    purpose that can't be derived (invalid scalar — astronomically rare).
    """
    if len(privkey) != 32:
        raise ValueError("privkey must be 32 bytes")
    try:
        pub_compressed = PrivateKey(privkey).public_key.format(compressed=True)
    except (ValueError, RuntimeError):  # pragma: no cover
        return WalletAddresses(p2pkh_bip44=None, p2sh_p2wpkh_bip49=None, p2wpkh_bip84=None)

    return WalletAddresses(
        p2pkh_bip44=_p2pkh_address(pub_compressed),
        p2sh_p2wpkh_bip49=_p2sh_p2wpkh_address(pub_compressed),
        p2wpkh_bip84=_p2wpkh_address(pub_compressed),
    )


__all__ = [
    "WalletAddresses",
    "address_from_pubkey",
    "addresses_from_privkey",
    "entropy_to_seed",
    "first_addresses",
]


# Suppress an unused-import lint by referencing PublicKey via a no-op alias.
# (Keeping the import is intentional — it documents the coincurve surface
# we depend on.)
_ = PublicKey
