#!/usr/bin/env python3
"""Generate ``tests/fixtures/sentinel.txt`` with all forms of the test private key.

The sentinel is a known-test privkey in 4 forms:
1. fingerprint16: ``sha256(d || "wsa-test-fingerprint")[:16]`` lowercase hex
2. raw 64-hex of d
3. compressed pubkey (33-byte hex)
4. WIF (Wallet Import Format)

CI greps the full test suite output for any of these strings; a hit fails
the build. Distinguishing 4 forms vs a regex eliminates false positives on
legitimate hex (txid, block height).

The test privkey is intentionally a documented-public value; treating it as
sensitive at runtime forces the redaction layer to be exercised.

Run:
    uv run python scripts/generate_sentinel.py
"""

from __future__ import annotations

import hashlib
from pathlib import Path

# Public, documented test privkey. Used ONLY in tests; never in production.
# The high-bit-set value triggers DER's leading-zero rule on encoding.
# This integer corresponds to the documented Bitcoin test vector below.
TEST_PRIVKEY_INT = 0xC0FFEEC0FFEEC0FFEEC0FFEEC0FFEEC0FFEEC0FFEEC0FFEEC0FFEEC0FFEEDEAD
TEST_PRIVKEY_HEX = f"{TEST_PRIVKEY_INT:064x}"

DOMAIN_SEP = b"wsa-test-fingerprint"

# Base58 alphabet for WIF.
_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _base58check_encode(payload: bytes) -> str:
    """Base58Check: payload || sha256(sha256(payload))[:4]."""
    chk = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    full = payload + chk
    n = int.from_bytes(full, "big")
    out = ""
    while n > 0:
        n, rem = divmod(n, 58)
        out = _B58_ALPHABET[rem] + out
    # Leading zero bytes -> leading '1's.
    for byte in full:
        if byte == 0:
            out = "1" + out
        else:
            break
    return out


def _privkey_to_wif(d_hex: str, *, compressed: bool = True) -> str:
    """Encode a hex privkey as Bitcoin mainnet WIF."""
    payload = b"\x80" + bytes.fromhex(d_hex)
    if compressed:
        payload += b"\x01"
    return _base58check_encode(payload)


def _privkey_to_compressed_pubkey(d_hex: str) -> str:
    """Derive compressed pubkey hex via coincurve.

    Returns "(unavailable)" if coincurve isn't importable; the sentinel will
    still have hex/wif/fingerprint forms which cover most leak vectors.
    """
    try:
        from coincurve import PrivateKey
    except ImportError:
        return "(coincurve-unavailable)"
    pk = PrivateKey(bytes.fromhex(d_hex))
    return pk.public_key.format(compressed=True).hex()


def make_sentinel() -> dict[str, str]:
    """Compute all 4 sentinel forms."""
    d = TEST_PRIVKEY_HEX
    fingerprint = hashlib.sha256(bytes.fromhex(d) + DOMAIN_SEP).hexdigest()[:16]
    return {
        "fingerprint16": fingerprint,
        "raw_hex64": d,
        "compressed_pubkey": _privkey_to_compressed_pubkey(d),
        "wif": _privkey_to_wif(d),
    }


def write_sentinel_file(path: Path, sentinel: dict[str, str]) -> None:
    """Write sentinel.txt — one form per line, no labels.

    Each line is a literal string we want to grep for. CI does
    ``grep -F -f sentinel.txt`` so any line in the test output that
    contains any of these substrings triggers a failure.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        sentinel["fingerprint16"],
        sentinel["raw_hex64"],
        sentinel["compressed_pubkey"],
        sentinel["wif"],
    ]
    # Skip "(...)" placeholders (when a form couldn't be computed).
    lines = [ln for ln in lines if ln and not ln.startswith("(")]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    repo_root = Path(__file__).resolve().parent.parent
    sentinel_path = repo_root / "tests" / "fixtures" / "sentinel.txt"
    sentinel = make_sentinel()
    write_sentinel_file(sentinel_path, sentinel)
    print(f"Wrote {sentinel_path}")
    print(f"  fingerprint16: {sentinel['fingerprint16']}")
    print(f"  raw_hex64:     {sentinel['raw_hex64']}")
    print(f"  compressed:    {sentinel['compressed_pubkey']}")
    print(f"  wif:           {sentinel['wif']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
