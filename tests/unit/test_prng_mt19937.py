"""Unit tests for ``prng.mt19937_cpp`` — validated against ``tools/ref.cpp``."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from wallet_self_audit.prng.mt19937_cpp import (
    MT19937,
    check_fixtures,
    entropy_from_timestamp,
)

_FIXTURE_PATH = Path(__file__).resolve().parents[1] / "fixtures" / "prng" / "mt19937_cpp_ref.json"


def test_check_fixtures_passes() -> None:
    assert check_fixtures() is True


@pytest.mark.skipif(not _FIXTURE_PATH.exists(), reason="C++ ref fixture missing")
def test_each_fixture_case_byte_identical() -> None:
    """Every (seed_seq_input, first_outputs) pair must match exactly."""
    cases = json.loads(_FIXTURE_PATH.read_text(encoding="utf-8"))["cases"]
    assert len(cases) >= 5, "fixture must have at least 5 cases"

    for case in cases:
        rng = MT19937.from_seed_seq([int(x) for x in case["seed_seq_input"]])
        n = len(case["first_outputs"])
        actual = [rng.next_uint32() for _ in range(n)]
        assert actual == [int(x) for x in case["first_outputs"]], (
            f"divergence at seed_seq={case['seed_seq_input']}"
        )


def test_init_genrand_canonical_first_output() -> None:
    """``init_genrand(5489)`` is the default-seeded mt19937 — known canonical."""
    rng = MT19937.from_init_genrand(5489)
    # The first output of the canonical reference mt19937 with default seed
    # is 3499211612 — published in countless tutorials.
    assert rng.next_uint32() == 3499211612


def test_state_must_be_n_long() -> None:
    with pytest.raises(ValueError, match="length 624"):
        MT19937([0] * 100)


def test_entropy_from_timestamp_12_words() -> None:
    """Sanity: 12-word entropy is 16 bytes."""
    e = entropy_from_timestamp(1577836800, n_words=12)
    assert len(e) == 16


def test_entropy_from_timestamp_24_words() -> None:
    e = entropy_from_timestamp(1577836800, n_words=24)
    assert len(e) == 32


def test_entropy_from_timestamp_unsupported_word_count() -> None:
    with pytest.raises(ValueError, match="unsupported n_words"):
        entropy_from_timestamp(1577836800, n_words=11)


def test_entropy_is_deterministic() -> None:
    """Same timestamp → same entropy bytes (idempotent)."""
    a = entropy_from_timestamp(1577836800)
    b = entropy_from_timestamp(1577836800)
    assert a == b


def test_different_timestamps_give_different_entropy() -> None:
    """Cheap sanity — adjacent timestamps must produce different entropy."""
    a = entropy_from_timestamp(1577836800)
    b = entropy_from_timestamp(1577836801)
    assert a != b
