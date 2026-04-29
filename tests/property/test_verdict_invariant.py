"""Hypothesis property tests for ``VerdictWithoutKey`` invariants."""

from __future__ import annotations

import json
import string

from hypothesis import given
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
    n_evidence=st.integers(min_value=0, max_value=5),
    n_checks=st.integers(min_value=0, max_value=5),
)
def test_valid_verdict_round_trips_through_json(
    confidence: float,
    status_finding: tuple[str, str],
    n_evidence: int,
    n_checks: int,
) -> None:
    """Random valid verdicts construct cleanly and JSON-roundtrip."""
    status, finding = status_finding
    txids = tuple(("a" * 64,) for _ in range(n_evidence))
    txids_flat = tuple(t for tup in txids for t in tup)
    checks = tuple(f"check_{i}" for i in range(n_checks))

    v = VerdictWithoutKey(
        address="bc1qexample",
        status=status,  # type: ignore[arg-type]
        finding=finding,  # type: ignore[arg-type]
        confidence=confidence,
        key_fingerprint=None if status == "SAFE" else "0123456789abcdef",
        recommendation="Test recommendation.",
        evidence_refs=txids_flat,
        audit_id="00000000-0000-0000-0000-000000000000",
        checks_performed=checks,
    )

    pub = v.to_public_json()
    serialized = json.dumps(pub)
    parsed = json.loads(serialized)
    assert parsed["status"] == status
    assert parsed["finding"] == finding


@given(s=st.text(alphabet=string.ascii_lowercase + string.digits, min_size=17))
def test_recommendation_with_too_many_hex_rejected(s: str) -> None:
    """If the random string happens to have > 16 hex chars, construction fails."""
    import pytest

    hex_chars = sum(1 for c in s if c in "0123456789abcdefABCDEF")
    if hex_chars <= 16:
        # Doesn't trigger the invariant; skip this case.
        return

    with pytest.raises(ValueError, match="possible private key leak"):
        VerdictWithoutKey(
            address="bc1qexample",
            status="SAFE",
            finding="none",
            confidence=0.99,
            key_fingerprint=None,
            recommendation=s,
            evidence_refs=(),
            audit_id="00000000-0000-0000-0000-000000000000",
            checks_performed=(),
        )
