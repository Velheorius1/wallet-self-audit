"""Hypothesis property tests for ``VerdictWithoutKey`` invariants."""

from __future__ import annotations

import json
import re

import pytest
from hypothesis import assume, given
from hypothesis import strategies as st

from wallet_self_audit.verdict import VerdictWithoutKey

_STATUS_FINDING = [
    ("SAFE", "none"),
    ("SUSPICIOUS", "none"),
    ("VULNERABLE", "r_collision"),
    ("VULNERABLE", "lattice_bias"),
    ("VULNERABLE", "weak_prng_milksad"),
    ("VULNERABLE", "weak_prng_randstorm"),
    ("VULNERABLE", "brainwallet"),
    ("SUSPICIOUS", "r_collision"),
]


@given(
    confidence=st.floats(min_value=0.0, max_value=1.0, allow_nan=False),
    status_finding=st.sampled_from(_STATUS_FINDING),
    txids=st.lists(
        st.text(alphabet="0123456789abcdef", min_size=64, max_size=64),
        min_size=0,
        max_size=5,
    ),
    n_checks=st.integers(min_value=0, max_value=5),
    audit_uuid=st.uuids(version=4),
)
def test_valid_verdict_round_trips_through_json(
    confidence: float,
    status_finding: tuple[str, str],
    txids: list[str],
    n_checks: int,
    audit_uuid: object,  # uuid.UUID, but typed as object for mypy/strict
) -> None:
    """Random valid verdicts construct cleanly and JSON-roundtrip.

    Real diversity here: each txid is independently generated 64-hex,
    each audit_id is a fresh UUID v4 from ``hypothesis.strategies.uuids``.
    The earlier version hard-coded the same txid and audit_id for every
    case, so the strategy was effectively a parametrize with duplicates.
    """
    status, finding = status_finding
    checks = tuple(f"check_{i}" for i in range(n_checks))

    v = VerdictWithoutKey(
        address="bc1qexample",
        status=status,  # type: ignore[arg-type]
        finding=finding,  # type: ignore[arg-type]
        confidence=confidence,
        key_fingerprint=None if status == "SAFE" else "0123456789abcdef",
        recommendation="Test recommendation.",
        evidence_refs=tuple(txids),
        audit_id=str(audit_uuid),
        checks_performed=checks,
    )

    pub = v.to_public_json()
    serialized = json.dumps(pub)
    parsed = json.loads(serialized)
    assert parsed["status"] == status
    assert parsed["finding"] == finding
    assert parsed["audit_id"] == str(audit_uuid)
    assert parsed["evidence_refs"] == txids


_HEX_ALPHABET = "0123456789abcdef"
_NON_HEX_ALPHABET = "ghijklmnopqrstuvwxyz .,!?-"


@given(
    prefix=st.text(alphabet=_NON_HEX_ALPHABET, max_size=40),
    suffix=st.text(alphabet=_NON_HEX_ALPHABET, max_size=40),
    hex_run=st.text(alphabet=_HEX_ALPHABET, min_size=17, max_size=128),
)
def test_recommendation_with_long_hex_run_rejected(prefix: str, suffix: str, hex_run: str) -> None:
    """A 17+ char contiguous hex run anywhere in the string triggers rejection.

    The leak-shape we defend against is a 32-byte private key rendered as
    64 contiguous hex chars; any contiguous run > 16 is suspicious.
    """
    leak_string = f"{prefix}{hex_run}{suffix}"

    with pytest.raises(ValueError, match="possible private key leak"):
        VerdictWithoutKey(
            address="bc1qexample",
            status="SAFE",
            finding="none",
            confidence=0.99,
            key_fingerprint=None,
            recommendation=leak_string,
            evidence_refs=(),
            audit_id="11111111-1111-1111-1111-111111111111",
            checks_performed=(),
        )


@given(
    text=st.text(alphabet=_NON_HEX_ALPHABET + _HEX_ALPHABET, min_size=0, max_size=300),
)
def test_recommendation_with_no_long_hex_run_accepted(text: str) -> None:
    """Strings without a 17-char contiguous hex run construct cleanly even
    when they contain many incidental hex characters (a-f letters in normal
    English words, etc.). This is the regression-test counterpart to the
    earlier total-count check that wrongly rejected real recommendations.
    """
    assume(not re.search(r"[0-9a-fA-F]{17,}", text))

    v = VerdictWithoutKey(
        address="bc1qexample",
        status="SAFE",
        finding="none",
        confidence=0.99,
        key_fingerprint=None,
        recommendation=text,
        evidence_refs=(),
        audit_id="11111111-1111-1111-1111-111111111111",
        checks_performed=(),
    )
    assert v.recommendation == text
