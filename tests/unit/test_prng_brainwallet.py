"""Unit tests for ``prng.brainwallet`` — public-passphrase detection."""

from __future__ import annotations

import hashlib

import pytest

from wallet_self_audit.prng.brainwallet import (
    BrainwalletHit,
    builtin_sample_wordlist,
    load_wordlist,
    scan_phrases,
)
from wallet_self_audit.prng.derive import addresses_from_privkey


def test_password_brainwallet_detected_via_p2pkh() -> None:
    """The classic 'password' brainwallet must match in the sample wordlist."""
    pk = hashlib.sha256(b"password").digest()
    addrs = addresses_from_privkey(pk)
    assert addrs.p2pkh_bip44 is not None

    hit = scan_phrases(frozenset({addrs.p2pkh_bip44}), n_workers=1)
    assert hit is not None
    assert isinstance(hit, BrainwalletHit)
    assert hit.matched_via == "p2pkh_bip44"
    # 'password' is at index 0 in the sample wordlist.
    assert hit.phrase_index == 0


def test_unknown_address_misses() -> None:
    miss = scan_phrases(frozenset({"bc1qzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"}), n_workers=1)
    assert miss is None


def test_empty_targets_raises() -> None:
    with pytest.raises(ValueError, match="non-empty"):
        scan_phrases(frozenset(), n_workers=1)


def test_load_wordlist_strips_blank_lines(tmp_path) -> None:
    p = tmp_path / "list.txt"
    p.write_text("alpha\n\nbeta\n  \n  gamma  \n", encoding="utf-8")
    out = load_wordlist(p)
    assert out == ("alpha", "beta", "gamma")


def test_builtin_sample_wordlist_contains_password() -> None:
    sample = builtin_sample_wordlist()
    assert "password" in sample
    assert "satoshi" in sample
    assert "correct horse battery staple" in sample


def test_user_wordlist_overrides_builtin() -> None:
    """If the user passes a wordlist, the builtin must NOT be searched."""
    pk_password = hashlib.sha256(b"password").digest()
    addrs = addresses_from_privkey(pk_password)
    assert addrs.p2pkh_bip44 is not None

    # User wordlist that does NOT contain 'password' — must miss.
    miss = scan_phrases(
        frozenset({addrs.p2pkh_bip44}),
        wordlist=("alpha", "beta", "gamma"),
        n_workers=1,
    )
    assert miss is None
