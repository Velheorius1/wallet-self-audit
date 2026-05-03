"""Recovery-detector unit tests — synthetic nonce reuse.

We deliberately construct a vulnerable wallet (signing two messages with
the same k) and assert that:
1. ``project_pubkey(r, s, z)`` returns a list including the known Q.
2. ``consistent_with_pubkey`` returns True for the right Q and False for
   any other Q.
3. ``collision_recovers_pubkey`` returns True for the synthetic case.

We must never end up with a Python int that *is* the recovered private
key. The recovery-detector only deals with public-key-side projections.
"""

from __future__ import annotations

import hashlib
import os

import pytest
from coincurve import PrivateKey

from wallet_self_audit.crypto.recovery_detector import (
    collision_recovers_pubkey,
    consistent_with_pubkey,
    fingerprint,
    project_pubkey,
)

_SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def _sign(z: int, d: int, k: int) -> tuple[int, int]:
    """Pure-Python ECDSA signing — only for tests."""
    pub = PrivateKey(k.to_bytes(32, "big")).public_key.format(compressed=False)
    rx = int.from_bytes(pub[1:33], "big")
    r = rx % _SECP256K1_N
    s = (pow(k, -1, _SECP256K1_N) * (z + r * d)) % _SECP256K1_N
    if r == 0 or s == 0:
        raise RuntimeError("degenerate signature")
    return r, s


@pytest.fixture
def reused_nonce_setup() -> tuple[int, int, int, int, int, int, bytes]:
    """Return (r, s_a, z_a, s_b, z_b, _ignore, Q_compressed) for one collision."""
    d = 0x1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF
    k = 0xFEDCBA0987654321FEDCBA0987654321FEDCBA0987654321FEDCBA0987654321
    z_a = int.from_bytes(hashlib.sha256(b"message a").digest(), "big") % _SECP256K1_N
    z_b = int.from_bytes(hashlib.sha256(b"message b").digest(), "big") % _SECP256K1_N
    r_a, s_a = _sign(z_a, d, k)
    r_b, s_b = _sign(z_b, d, k)
    assert r_a == r_b, "k reused → r must match"
    Q = PrivateKey(d.to_bytes(32, "big")).public_key.format(compressed=True)
    return r_a, s_a, z_a, s_b, z_b, 0, Q


def test_project_pubkey_includes_real_Q(
    reused_nonce_setup: tuple[int, int, int, int, int, int, bytes],
) -> None:
    r, s_a, z_a, *_, Q = reused_nonce_setup
    candidates = project_pubkey(r, s_a, z_a)
    assert Q in candidates


def test_consistent_with_pubkey_positive(
    reused_nonce_setup: tuple[int, int, int, int, int, int, bytes],
) -> None:
    r, s_a, z_a, *_, Q = reused_nonce_setup
    assert consistent_with_pubkey(r, s_a, z_a, Q) is True


def test_consistent_with_pubkey_negative(
    reused_nonce_setup: tuple[int, int, int, int, int, int, bytes],
) -> None:
    r, s_a, z_a, *_ = reused_nonce_setup
    random_d = int.from_bytes(os.urandom(32), "big") % (_SECP256K1_N - 1) + 1
    other_Q = PrivateKey(random_d.to_bytes(32, "big")).public_key.format(compressed=True)
    assert consistent_with_pubkey(r, s_a, z_a, other_Q) is False


def test_collision_recovers_pubkey_positive(
    reused_nonce_setup: tuple[int, int, int, int, int, int, bytes],
) -> None:
    r, s_a, z_a, s_b, z_b, _, Q = reused_nonce_setup
    assert collision_recovers_pubkey(r, s_a, z_a, s_b, z_b, Q) is True


def test_collision_recovers_pubkey_wrong_Q(
    reused_nonce_setup: tuple[int, int, int, int, int, int, bytes],
) -> None:
    r, s_a, z_a, s_b, z_b, _, _Q = reused_nonce_setup
    random_d = int.from_bytes(os.urandom(32), "big") % (_SECP256K1_N - 1) + 1
    bad_Q = PrivateKey(random_d.to_bytes(32, "big")).public_key.format(compressed=True)
    assert collision_recovers_pubkey(r, s_a, z_a, s_b, z_b, bad_Q) is False


def test_project_pubkey_invalid_r() -> None:
    with pytest.raises(ValueError, match="r out of range"):
        project_pubkey(0, 1, 1)


def test_project_pubkey_invalid_s() -> None:
    with pytest.raises(ValueError, match="s out of range"):
        project_pubkey(1, 0, 1)


def test_fingerprint_is_16_lowercase_hex(
    reused_nonce_setup: tuple[int, int, int, int, int, int, bytes],
) -> None:
    r, *_, Q = reused_nonce_setup
    fp = fingerprint(
        pubkey_compressed=Q,
        r=r,
        txid_a="aa" * 32,
        txid_b="bb" * 32,
    )
    assert len(fp) == 16
    assert all(c in "0123456789abcdef" for c in fp)


def test_fingerprint_changes_with_inputs(
    reused_nonce_setup: tuple[int, int, int, int, int, int, bytes],
) -> None:
    r, *_, Q = reused_nonce_setup
    fp1 = fingerprint(pubkey_compressed=Q, r=r, txid_a="aa" * 32, txid_b="bb" * 32)
    fp2 = fingerprint(pubkey_compressed=Q, r=r, txid_a="aa" * 32, txid_b="cc" * 32)
    assert fp1 != fp2
