"""Unit tests for strict DER signature parser."""

from __future__ import annotations

import pytest

from wallet_self_audit.crypto.der import (
    SECP256K1_N,
    SECP256K1_N_HALF,
    DERParseError,
    encode_der,
    is_low_s,
    normalize_low_s,
    parse_der,
)


# ---------------------------------------------------------------------------
# Round-trip tests
# ---------------------------------------------------------------------------
def test_roundtrip_canonical_low_s() -> None:
    r = 0x1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF
    s = SECP256K1_N_HALF - 1
    encoded = encode_der(r, s)
    rr, ss = parse_der(encoded)
    assert (rr, ss) == (r, s)


def test_roundtrip_high_r_with_msb_set() -> None:
    """When r's MSB is set, encoding must prepend 0x00 to keep it positive."""
    r = (1 << 255) - 1  # Has high bit set in 256-bit representation
    s = 12345
    encoded = encode_der(r, s)
    # Verify the leading zero rule: r body should start with 0x00 if MSB set.
    rr, ss = parse_der(encoded)
    assert (rr, ss) == (r, s)


def test_roundtrip_small_r_and_s() -> None:
    encoded = encode_der(1, 1)
    assert parse_der(encoded) == (1, 1)


# ---------------------------------------------------------------------------
# Negative tests — malformed DER
# ---------------------------------------------------------------------------
def test_reject_wrong_sequence_tag() -> None:
    sig = b"\x31\x06\x02\x01\x01\x02\x01\x01"
    with pytest.raises(DERParseError, match="SEQUENCE tag"):
        parse_der(sig)


def test_reject_too_short() -> None:
    with pytest.raises(DERParseError, match="too short"):
        parse_der(b"\x30\x02\x02\x01")


def test_reject_extra_trailing_bytes() -> None:
    valid = encode_der(1, 1)
    with pytest.raises(DERParseError):
        parse_der(valid + b"\x00")


def test_reject_unnecessary_leading_zero() -> None:
    """0x00 0x01 (MSB clear) is invalid encoding for the integer 1."""
    # SEQUENCE { INTEGER 0x00, 0x01 (= 1, but encoded with extra 0x00) | INTEGER 1 }
    bad = bytes(
        [
            0x30, 0x08,
            0x02, 0x02, 0x00, 0x01,  # bad r: leading 0x00 unnecessary
            0x02, 0x02, 0x00, 0x01,  # same for s
        ]
    )
    with pytest.raises(DERParseError, match="unnecessary leading"):
        parse_der(bad)


def test_reject_negative_integer_msb_set() -> None:
    """An integer with MSB set in the FIRST byte is interpreted as negative."""
    bad = bytes(
        [
            0x30, 0x06,
            0x02, 0x01, 0x80,  # r = -128 in two's complement
            0x02, 0x01, 0x01,
        ]
    )
    with pytest.raises(DERParseError, match="negative"):
        parse_der(bad)


def test_reject_r_zero() -> None:
    bad = bytes(
        [
            0x30, 0x06,
            0x02, 0x01, 0x00,  # r = 0
            0x02, 0x01, 0x01,
        ]
    )
    with pytest.raises(DERParseError):
        parse_der(bad)


def test_reject_r_above_n() -> None:
    """r >= N is invalid by spec."""
    r = SECP256K1_N + 1
    s = 1
    # Skip encode_der validation by constructing manually.
    r_bytes = r.to_bytes(33, "big")  # extra byte to fit, with leading 0x00
    sig = b"\x30" + bytes([3 + len(r_bytes) + 3]) + b"\x02" + bytes([len(r_bytes)]) + r_bytes + b"\x02\x01\x01"
    with pytest.raises(DERParseError, match="out of range"):
        parse_der(sig)


# ---------------------------------------------------------------------------
# Low-s helpers
# ---------------------------------------------------------------------------
def test_is_low_s() -> None:
    assert is_low_s(1)
    assert is_low_s(SECP256K1_N_HALF)
    assert not is_low_s(SECP256K1_N_HALF + 1)
    assert not is_low_s(SECP256K1_N - 1)


def test_normalize_low_s_idempotent() -> None:
    assert normalize_low_s(1) == 1
    assert normalize_low_s(SECP256K1_N_HALF) == SECP256K1_N_HALF


def test_normalize_high_s_to_low() -> None:
    high = SECP256K1_N - 1
    low = normalize_low_s(high)
    assert is_low_s(low)
    # Normalizing again is idempotent.
    assert normalize_low_s(low) == low
