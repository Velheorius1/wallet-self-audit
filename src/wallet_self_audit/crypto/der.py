"""Strict DER signature parser for ECDSA secp256k1 signatures.

Implements RFC 6979 + BIP-66 strict DER encoding rules:
- ASN.1 SEQUENCE wrapping two INTEGERs.
- INTEGERs are MSB-set-aware (leading 0x00 if high bit set).
- No extra bytes.
- BIP-62 low-s normalization helper.

This is a defensive parser — we reject malformed signatures rather than
trying to recover. Bitcoin Core has been strict since 2015; legitimate
signatures all parse cleanly.

References:
- RFC 6979: https://datatracker.ietf.org/doc/html/rfc6979
- BIP-62 (low-s): https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki
- BIP-66 (strict DER): https://github.com/bitcoin/bips/blob/master/bip-0066.mediawiki
"""

from __future__ import annotations

# secp256k1 curve order N.
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
SECP256K1_N_HALF = SECP256K1_N // 2


class DERParseError(ValueError):
    """Raised when a DER signature is malformed."""


def parse_der(sig: bytes) -> tuple[int, int]:
    """Parse a DER-encoded ECDSA signature into (r, s) integers.

    Args:
        sig: DER-encoded signature bytes (no sighash type byte).

    Returns:
        Tuple of (r, s) as Python integers in [1, N-1].

    Raises:
        DERParseError: on any encoding violation.
    """
    if not isinstance(sig, (bytes, bytearray, memoryview)):  # pyright: ignore[reportUnnecessaryIsInstance]
        raise DERParseError(f"sig must be bytes-like, got {type(sig).__name__}")
    sig = bytes(sig)

    # SEQUENCE (0x30) header.
    if len(sig) < 8:
        raise DERParseError(f"signature too short: {len(sig)} bytes")
    if sig[0] != 0x30:
        raise DERParseError(f"expected SEQUENCE tag 0x30, got 0x{sig[0]:02x}")

    seq_len = sig[1]
    # Length of the SEQUENCE body.
    if seq_len + 2 != len(sig):
        raise DERParseError(
            f"SEQUENCE length mismatch: declared {seq_len}, available {len(sig) - 2}"
        )

    # First INTEGER: r.
    if sig[2] != 0x02:
        raise DERParseError(f"expected INTEGER tag 0x02 for r, got 0x{sig[2]:02x}")
    r_len = sig[3]
    if r_len == 0:
        raise DERParseError("r length is zero")
    r_start = 4
    r_end = r_start + r_len
    if r_end > len(sig):
        raise DERParseError("r length exceeds signature")
    r_bytes = sig[r_start:r_end]
    _validate_integer_encoding(r_bytes, "r")

    # Second INTEGER: s.
    s_tag_idx = r_end
    if s_tag_idx >= len(sig):
        raise DERParseError("missing s integer")
    if sig[s_tag_idx] != 0x02:
        raise DERParseError(f"expected INTEGER tag 0x02 for s, got 0x{sig[s_tag_idx]:02x}")
    s_len = sig[s_tag_idx + 1]
    if s_len == 0:
        raise DERParseError("s length is zero")
    s_start = s_tag_idx + 2
    s_end = s_start + s_len
    if s_end != len(sig):
        raise DERParseError(f"trailing bytes after s: expected end at {s_end}, got {len(sig)}")
    s_bytes = sig[s_start:s_end]
    _validate_integer_encoding(s_bytes, "s")

    r = int.from_bytes(r_bytes, "big")
    s = int.from_bytes(s_bytes, "big")

    if not 1 <= r < SECP256K1_N:
        raise DERParseError("r out of range [1, N-1]")
    if not 1 <= s < SECP256K1_N:
        raise DERParseError("s out of range [1, N-1]")

    return r, s


def _validate_integer_encoding(value: bytes, name: str) -> None:
    """Validate strict DER INTEGER encoding rules for *value*.

    Rules:
    - Non-empty.
    - No unnecessary leading zero (unless required by MSB-set rule).
    - First byte's high bit MUST be zero (positive integer).
    """
    if not value:
        raise DERParseError(f"{name} INTEGER is empty")
    # Negative would have MSB set; we only accept positives.
    if value[0] & 0x80:
        raise DERParseError(f"{name} INTEGER appears negative (MSB set)")
    # Unnecessary leading zero: 0x00 followed by a byte without MSB set.
    if len(value) >= 2 and value[0] == 0x00 and not (value[1] & 0x80):
        raise DERParseError(f"{name} INTEGER has unnecessary leading 0x00")


def is_low_s(s: int) -> bool:
    """Return True iff *s* satisfies BIP-62 low-s rule (s <= N/2)."""
    return s <= SECP256K1_N_HALF


def normalize_low_s(s: int) -> int:
    """Return the low-s form of *s*. Idempotent."""
    if is_low_s(s):
        return s
    return SECP256K1_N - s


def encode_der(r: int, s: int) -> bytes:
    """Encode (r, s) into strict DER. Inverse of ``parse_der``.

    Used for testing round-trips and synthetic vector generation. Production
    code typically receives DER from libsecp256k1 directly.
    """
    if not 1 <= r < SECP256K1_N:
        raise ValueError("r out of range")
    if not 1 <= s < SECP256K1_N:
        raise ValueError("s out of range")

    def _encode_int(value: int) -> bytes:
        # Minimal byte-length representation, big-endian.
        length = (value.bit_length() + 7) // 8 or 1
        body = value.to_bytes(length, "big")
        # If MSB is set, prepend 0x00 to disambiguate from negative.
        if body[0] & 0x80:
            body = b"\x00" + body
        return b"\x02" + bytes([len(body)]) + body

    r_enc = _encode_int(r)
    s_enc = _encode_int(s)
    body = r_enc + s_enc
    return b"\x30" + bytes([len(body)]) + body
