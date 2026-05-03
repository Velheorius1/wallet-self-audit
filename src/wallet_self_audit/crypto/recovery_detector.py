"""Verify-by-pubkey-projection — recover Q from (r, s, z) WITHOUT materializing d.

Standard ECDSA recovery formula::

    d = (s_a * z_b - s_b * z_a) / ((s_b - s_a) * r)  mod n

would compute a 32-byte private key in a Python int — and Python ints
cannot be reliably zeroed (small-int interning, refcounting, GC). Even
``del`` is best-effort. So we never compute ``d`` at all.

Instead, given ``(r, s, z)`` and a known public key ``Q``, we use the
ECDSA verification identity::

    Q = (s * R - z * G) / r  mod n

where ``R`` is one of the (up to four) curve points whose x-coordinate is
``r`` or ``r + n``. We project this through ``coincurve`` group operations
on libsecp256k1 — the scalar arithmetic happens in C and the recovered
pubkey is compared as bytes.

Output:
- ``True`` (consistent with ``Q``) — the wallet that owns ``Q`` produced
  this signature with this ``(r, s, z)`` triple. If two distinct (s, z)
  triples for the same ``r`` both project to ``Q``, ``Q`` is recoverable
  by anyone.
- ``False`` — the signature is not consistent with ``Q`` (likely a
  different signing key used the same ``r`` by coincidence — astronomical
  but the type system has to handle it).

We never return a private key, never log one, never materialize one.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Final

from coincurve import PrivateKey, PublicKey

# secp256k1 parameters.
_SECP256K1_N: Final[int] = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_SECP256K1_P: Final[int] = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_SECP256K1_B: Final[int] = 7

# Domain separator for fingerprints. Distinct from PRNG audit's separator.
_FINGERPRINT_DOMAIN: Final[bytes] = b"wallet-self-audit/v1.0/nonce-fingerprint"


@dataclass(frozen=True, slots=True)
class CollisionEvidence:
    """Evidence that two signatures used the same r against pubkey Q.

    All fields are public-safe — no private key bytes anywhere. The
    ``key_fingerprint`` is a domain-separated SHA-256 of the public
    inputs only; it deterministically identifies *this finding* without
    leaking secrets.
    """

    pubkey_compressed_hex: str  # 66-char hex, public chain data
    r_hex: str  # 64-char hex
    txid_a: str  # 64-char hex
    txid_b: str  # 64-char hex
    key_fingerprint: str  # 16-char hex — sha256 of public inputs


def _modinv(a: int, m: int) -> int:
    """Compute the modular inverse of ``a`` modulo ``m`` (m must be prime)."""
    # Python 3.8+ supports pow(a, -1, m).
    return pow(a, -1, m)


def _y_from_x_secp256k1(x: int, want_odd: bool) -> int | None:
    """Return the y-coordinate of the secp256k1 point with x = ``x``.

    ``want_odd`` selects between the two roots. Returns ``None`` if no
    root exists (x is not on the curve).
    """
    if not 0 <= x < _SECP256K1_P:
        return None
    rhs = (pow(x, 3, _SECP256K1_P) + _SECP256K1_B) % _SECP256K1_P
    # secp256k1's prime is congruent to 3 mod 4, so a square root is
    # rhs**((p+1)/4) mod p when one exists.
    y = pow(rhs, (_SECP256K1_P + 1) // 4, _SECP256K1_P)
    if (y * y) % _SECP256K1_P != rhs:
        return None
    if (y & 1) != int(want_odd):
        y = _SECP256K1_P - y
    return y


def _r_candidates(r: int) -> list[bytes]:
    """Return up to 4 compressed-pubkey candidates for ``R`` (the nonce point).

    For a given ``r`` (the x-coordinate truncated to ``r mod n``), there
    are up to four ECDSA recovery candidates:
        * x = r,    y even or odd
        * x = r+n,  y even or odd  (only if r + n < p)
    """
    out: list[bytes] = []
    for delta in (0, _SECP256K1_N) if r + _SECP256K1_N < _SECP256K1_P else (0,):
        x = r + delta
        for want_odd in (False, True):
            y = _y_from_x_secp256k1(x, want_odd)
            if y is None:
                continue
            prefix = 0x03 if want_odd else 0x02
            out.append(bytes([prefix]) + x.to_bytes(32, "big"))
    return out


def _scalar_mod_n_to_bytes(x: int) -> bytes:
    """Reduce ``x`` mod n and serialize as a 32-byte big-endian scalar."""
    return (x % _SECP256K1_N).to_bytes(32, "big")


def project_pubkey(r: int, s: int, z: int) -> list[bytes]:
    """Return all candidate pubkeys consistent with ``(r, s, z)`` (compressed).

    The list contains up to four PublicKey-compressed bytestrings
    corresponding to the up-to-four R candidates. The caller compares
    each candidate against a known Q to decide consistency.

    Args:
        r: ECDSA r value, in [1, n-1].
        s: ECDSA s value, in [1, n-1].
        z: Sighash z (already a Python int from ``int.from_bytes(..., 'big')``).

    Returns:
        Up to 4 compressed pubkey bytestrings.
    """
    if not 0 < r < _SECP256K1_N:
        raise ValueError("r out of range")
    if not 0 < s < _SECP256K1_N:
        raise ValueError("s out of range")

    r_inv = _modinv(r, _SECP256K1_N)
    u1_int = (-z * r_inv) % _SECP256K1_N  # scalar for G
    u2_int = (s * r_inv) % _SECP256K1_N  # scalar for R

    out: list[bytes] = []
    # u1 * G = PrivateKey(u1).public_key. Note: PrivateKey rejects 0 — handle.
    if u1_int == 0:
        # Degenerate; with z != 0 this only happens if the inverse is 0 mod n.
        return out
    g_term = PublicKey.from_secret(_scalar_mod_n_to_bytes(u1_int))

    for r_pub_bytes in _r_candidates(r):
        try:
            r_pub = PublicKey(r_pub_bytes)
            r_term = r_pub.multiply(_scalar_mod_n_to_bytes(u2_int))
            q_recovered = PublicKey.combine_keys([g_term, r_term])
            out.append(q_recovered.format(compressed=True))
        except (ValueError, RuntimeError):
            continue
    return out


def consistent_with_pubkey(r: int, s: int, z: int, known_pubkey_compressed: bytes) -> bool:
    """Return True iff one of the projected candidates matches ``known_pubkey``.

    The pubkey must be in 33-byte compressed form. Uncompressed callers
    should re-compress through coincurve first.
    """
    if len(known_pubkey_compressed) != 33:
        # Try to coerce uncompressed → compressed.
        try:
            known_pubkey_compressed = PublicKey(known_pubkey_compressed).format(compressed=True)
        except (ValueError, RuntimeError) as exc:
            raise ValueError("invalid known_pubkey bytes") from exc

    candidates = project_pubkey(r, s, z)
    return known_pubkey_compressed in candidates


def collision_recovers_pubkey(
    r: int,
    s_a: int,
    z_a: int,
    s_b: int,
    z_b: int,
    known_pubkey_compressed: bytes,
) -> bool:
    """Return True iff *both* signatures are consistent with the known Q.

    This is the operational definition of a recoverable nonce-reuse:
    when two signatures share an ``r`` and both project (via ECDSA
    verification math) to the wallet's known public key, *any observer
    of the chain can solve for ``d``*. We do not solve for it ourselves.

    Returns ``True`` for the VULNERABLE branch. ``False`` for "different
    keys happened to land on the same r" (vanishingly rare).
    """
    return consistent_with_pubkey(r, s_a, z_a, known_pubkey_compressed) and (
        consistent_with_pubkey(r, s_b, z_b, known_pubkey_compressed)
    )


def fingerprint(
    *,
    pubkey_compressed: bytes,
    r: int,
    txid_a: str,
    txid_b: str,
) -> str:
    """Compute a 16-hex public fingerprint for an r-collision finding.

    Inputs are all public chain data — the fingerprint is deterministic
    and reproducible by any auditor with the same evidence. It is *not*
    derived from the recovered private key (which we never compute).
    """
    h = hashlib.sha256()
    h.update(_FINGERPRINT_DOMAIN)
    h.update(b":")
    h.update(pubkey_compressed)
    h.update(b":")
    h.update(r.to_bytes(32, "big"))
    h.update(b":")
    h.update(bytes.fromhex(txid_a))
    h.update(b":")
    h.update(bytes.fromhex(txid_b))
    return h.hexdigest()[:16]


# Suppress "unused import" — PrivateKey is referenced via from_secret only.
_ = PrivateKey


__all__ = [
    "CollisionEvidence",
    "collision_recovers_pubkey",
    "consistent_with_pubkey",
    "fingerprint",
    "project_pubkey",
]
