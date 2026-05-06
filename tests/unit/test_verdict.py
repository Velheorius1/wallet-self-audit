"""Unit tests for ``VerdictWithoutKey`` — the central output contract.

Invariants tested:
- frozen=True: ``setattr`` raises ``FrozenInstanceError``.
- slots=True: ``v.__dict__`` raises ``AttributeError``; cannot inject new fields.
- ``evidence_refs`` is ``tuple`` (immutable even on a frozen instance).
- ``__post_init__`` rejects:
  - Free-form text fields with a contiguous hex *run* longer than 16 chars
    (catches privkey-shaped leaks while accepting natural-language strings).
  - confidence outside [0, 1].
  - key_fingerprint not exactly 16 lowercase hex.
  - non-tuple evidence_refs / checks_performed.
  - SAFE status with finding != "none".
- ``to_public_json`` returns exactly the allowlisted fields.
"""

from __future__ import annotations

import dataclasses

import pytest

from wallet_self_audit.verdict import VerdictWithoutKey


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _safe_verdict(**overrides: object) -> VerdictWithoutKey:
    """Construct a SAFE verdict with default valid fields, override-able."""
    defaults: dict[str, object] = {
        "address": "bc1qexample0000000000000000000000000000000",
        "status": "SAFE",
        "finding": "none",
        "confidence": 0.99,
        "key_fingerprint": None,
        "recommendation": "No issues detected.",
        "evidence_refs": (),
        "audit_id": "00000000-0000-0000-0000-000000000000",
        "checks_performed": ("milk_sad", "randstorm"),
    }
    defaults.update(overrides)
    return VerdictWithoutKey(**defaults)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# 1. Construction succeeds with valid inputs.
# ---------------------------------------------------------------------------
def test_safe_verdict_constructs_cleanly() -> None:
    v = _safe_verdict()
    assert v.status == "SAFE"
    assert v.finding == "none"


def test_vulnerable_verdict_constructs_with_fingerprint() -> None:
    v = _safe_verdict(
        status="VULNERABLE",
        finding="r_collision",
        confidence=0.99,
        key_fingerprint="abcdef0123456789",
        recommendation="Move funds to a fresh wallet now.",
    )
    assert v.status == "VULNERABLE"
    assert v.key_fingerprint == "abcdef0123456789"


# ---------------------------------------------------------------------------
# 2. Frozen / slots — cannot mutate.
# ---------------------------------------------------------------------------
def test_setattr_raises_frozen_instance_error() -> None:
    v = _safe_verdict()
    with pytest.raises(dataclasses.FrozenInstanceError):
        v.status = "VULNERABLE"  # type: ignore[misc]


def test_no_dict_attribute() -> None:
    """slots=True means no __dict__; cannot inject new attributes."""
    v = _safe_verdict()
    with pytest.raises(AttributeError):
        _ = v.__dict__  # type: ignore[attr-defined]


def test_cannot_inject_attribute_via_object_setattr() -> None:
    """object.__setattr__ also fails on slots=True frozen dataclass."""
    v = _safe_verdict()
    with pytest.raises((AttributeError, dataclasses.FrozenInstanceError)):
        object.__setattr__(v, "privkey", "deadbeef" * 8)


# ---------------------------------------------------------------------------
# 3. evidence_refs is tuple (frozen-by-value).
# ---------------------------------------------------------------------------
def test_evidence_refs_is_tuple() -> None:
    v = _safe_verdict()
    assert isinstance(v.evidence_refs, tuple)


def test_evidence_refs_cannot_append() -> None:
    """tuples have no .append; even on a frozen instance, this would fail
    if evidence_refs were a list (frozen is shallow)."""
    v = _safe_verdict()
    with pytest.raises(AttributeError):
        v.evidence_refs.append("dead" * 16)  # type: ignore[attr-defined]


def test_evidence_refs_validates_64hex() -> None:
    valid_txid = "a" * 64
    v = _safe_verdict(evidence_refs=(valid_txid,))
    assert v.evidence_refs == (valid_txid,)


def test_evidence_refs_rejects_non_64hex() -> None:
    with pytest.raises(ValueError, match="64-char lowercase hex"):
        _safe_verdict(evidence_refs=("not_a_txid",))


def test_evidence_refs_rejects_uppercase_hex() -> None:
    with pytest.raises(ValueError, match="64-char lowercase hex"):
        _safe_verdict(evidence_refs=("A" * 64,))


# ---------------------------------------------------------------------------
# 4. checks_performed required (kills false-SAFE failure mode).
# ---------------------------------------------------------------------------
def test_checks_performed_must_be_tuple() -> None:
    with pytest.raises(TypeError, match="checks_performed must be tuple"):
        _safe_verdict(checks_performed=["milk_sad"])  # type: ignore[arg-type]


def test_checks_performed_can_be_empty_tuple() -> None:
    """Empty tuple allowed for terminal-error cases; not enforced at type level."""
    v = _safe_verdict(checks_performed=())
    assert v.checks_performed == ()


# ---------------------------------------------------------------------------
# 5. confidence range.
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("conf", [-0.1, 1.1, 2.0, -10.0])
def test_confidence_out_of_range_raises(conf: float) -> None:
    with pytest.raises(ValueError, match="confidence must be in"):
        _safe_verdict(confidence=conf)


@pytest.mark.parametrize("conf", [0.0, 0.5, 1.0])
def test_confidence_in_range_accepted(conf: float) -> None:
    v = _safe_verdict(confidence=conf)
    assert v.confidence == conf


def test_confidence_bool_rejected() -> None:
    """``bool`` is a subclass of ``int`` so ``True`` would silently pass the
    range check (``True == 1``). Reject explicitly to close that channel."""
    with pytest.raises(TypeError, match="confidence must be int or float, got bool"):
        _safe_verdict(confidence=True)  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="confidence must be int or float, got bool"):
        _safe_verdict(confidence=False)  # type: ignore[arg-type]


def test_confidence_non_numeric_rejected() -> None:
    with pytest.raises(TypeError, match="confidence must be int or float"):
        _safe_verdict(confidence="0.5")  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="confidence must be int or float"):
        _safe_verdict(confidence=None)  # type: ignore[arg-type]


def test_confidence_int_in_range_accepted() -> None:
    """Plain int is accepted for arithmetic convenience (e.g. ``confidence=1``)."""
    v = _safe_verdict(confidence=0)
    assert v.confidence == 0
    v = _safe_verdict(confidence=1)
    assert v.confidence == 1


# ---------------------------------------------------------------------------
# 6. key_fingerprint format.
# ---------------------------------------------------------------------------
def test_key_fingerprint_none_allowed() -> None:
    v = _safe_verdict(key_fingerprint=None)
    assert v.key_fingerprint is None


def test_key_fingerprint_16_lowercase_hex_accepted() -> None:
    v = _safe_verdict(
        status="VULNERABLE",
        finding="r_collision",
        key_fingerprint="0123456789abcdef",
        recommendation="Move funds now.",
    )
    assert v.key_fingerprint == "0123456789abcdef"


@pytest.mark.parametrize(
    "bad",
    [
        "0123456789ABCDEF",  # uppercase
        "0123456789abcde",  # 15 chars
        "0123456789abcdefa",  # 17 chars
        "0123456789abcdefg",  # non-hex
        "",
    ],
)
def test_key_fingerprint_invalid_rejected(bad: str) -> None:
    with pytest.raises(ValueError, match="key_fingerprint"):
        _safe_verdict(
            status="VULNERABLE",
            finding="r_collision",
            key_fingerprint=bad,
            recommendation="Move funds now.",
        )


# ---------------------------------------------------------------------------
# 7. Class invariant: contiguous hex *run* > 16 chars in free-form text rejected.
#    The check is on a contiguous run, not a total count, so natural-language
#    recommendations (which contain many incidental a-f letters but never a
#    17-char unbroken hex sequence) pass through unchanged.
# ---------------------------------------------------------------------------
def test_recommendation_with_long_hex_rejected() -> None:
    """A 64-hex string in recommendation looks like a leaked privkey."""
    leak = "abcdef" * 12  # 72 hex chars
    with pytest.raises(ValueError, match="possible private key leak"):
        _safe_verdict(recommendation=f"Found something: {leak}")


def test_recommendation_with_exact_17_char_hex_run_rejected() -> None:
    """Boundary: a 17-char contiguous hex run is the smallest rejected value."""
    with pytest.raises(ValueError, match="possible private key leak"):
        _safe_verdict(recommendation="see: " + "0" * 17)


def test_recommendation_with_exact_16_char_hex_run_accepted() -> None:
    """Boundary: exactly 16 contiguous hex chars is allowed."""
    v = _safe_verdict(recommendation="hint: 0123456789abcdef")
    assert "0123456789abcdef" in v.recommendation


def test_recommendation_two_short_hex_runs_separated_by_non_hex_accepted() -> None:
    """Two 16-char hex runs separated by a space carry no contiguous 17-run."""
    v = _safe_verdict(recommendation="0123456789abcdef DEADBEEFCAFEBABE")
    assert "0123456789abcdef" in v.recommendation


@pytest.mark.parametrize(
    "rec",
    [
        # Realistic recommendations that contain many incidental a-f letters
        # but no 17-char hex run. These regressed under the old total-count
        # check (the longest, 172 chars / 52 incidental hex chars, failed).
        (
            "Move funds to a freshly-generated wallet immediately. The detected "
            "r-collision means anyone watching the chain can derive your private "
            "key from public signature data alone."
        ),
        (
            "Generate a new seed in an audited wallet (Sparrow, Bitcoin Core 25+, "
            "Electrum 4.5+) and migrate the balance before the attacker re-uses "
            "the recovered key."
        ),
        (
            "Brainwallet phrase detected: change to a fresh BIP-39 seed from a "
            "secure source, then move funds. Do not re-use the same passphrase "
            "anywhere else, including for derived addresses."
        ),
        # Long form using a-f heavy English words
        (
            "Suspicious entropy detected: aborted, bad fold cafe, decade. "
            "Recommendation: defer further deposits until a clean seed is "
            "available."
        ),
    ],
)
def test_realistic_recommendation_accepted(rec: str) -> None:
    """Regression: the old total-hex-count check rejected real recommendations.
    The contiguous-run check accepts them while still rejecting privkey-shaped
    hex leaks (covered by ``test_recommendation_with_long_hex_rejected``).
    """
    v = _safe_verdict(recommendation=rec)
    assert v.recommendation == rec


# Note: we don't test the hex-run check on ``finding`` because the Literal
# type check fires first for any invalid value, and no valid Finding literal
# contains a 17-char hex run by design.


# ---------------------------------------------------------------------------
# 7b. audit_id must parse as a valid UUID — closes the channel where a
#     32-/48-hex segment of a private key impersonates an audit_id.
# ---------------------------------------------------------------------------
def test_audit_id_valid_uuid_with_dashes_accepted() -> None:
    v = _safe_verdict(audit_id="11111111-2222-3333-4444-555555555555")
    assert v.audit_id == "11111111-2222-3333-4444-555555555555"


def test_audit_id_valid_uuid_hex_accepted() -> None:
    """``uuid.UUID`` parses 32-hex form too (no dashes)."""
    v = _safe_verdict(audit_id="11111111222233334444555555555555")
    assert v.audit_id == "11111111222233334444555555555555"


@pytest.mark.parametrize(
    "bad",
    [
        # Privkey-shape: 48 hex chars, longer than UUID hex form
        "deadbeefcafebabe1234567890abcdefdeadbeefcafebabe",
        # Privkey-shape: 32 hex but wrong format (no UUID structure rules)
        # 32 chars of pure 'g' — uuid.UUID rejects (g not hex)
        "gggggggggggggggggggggggggggggggg",
        # Random non-UUID string
        "not-a-uuid",
        # Empty
        "",
        # Almost-UUID with wrong group count
        "11111111-2222-3333-4444",
    ],
)
def test_audit_id_invalid_uuid_rejected(bad: str) -> None:
    with pytest.raises(ValueError, match="audit_id must be a valid UUID"):
        _safe_verdict(audit_id=bad)


# ---------------------------------------------------------------------------
# 7c. Subclassing is forbidden — a subclass overriding ``__post_init__``
#     would bypass every leak-prevention check.
# ---------------------------------------------------------------------------
def test_cannot_subclass_verdict_without_key() -> None:
    from wallet_self_audit.verdict import VerdictWithoutKey

    with pytest.raises(TypeError, match="VerdictWithoutKey is @final"):

        class _Evil(VerdictWithoutKey):
            pass


# ---------------------------------------------------------------------------
# 8. Status / finding consistency.
# ---------------------------------------------------------------------------
def test_safe_with_nonzero_finding_rejected() -> None:
    with pytest.raises(ValueError, match="status=SAFE requires finding=none"):
        _safe_verdict(status="SAFE", finding="r_collision")


def test_invalid_status_rejected() -> None:
    with pytest.raises(ValueError, match="invalid status"):
        _safe_verdict(status="MAYBE_OK")  # type: ignore[arg-type]


def test_invalid_finding_rejected() -> None:
    with pytest.raises(ValueError, match="invalid finding"):
        _safe_verdict(
            status="VULNERABLE",
            finding="apocalypse",  # type: ignore[arg-type]
        )


# ---------------------------------------------------------------------------
# 9. to_public_json — explicit allowlist.
# ---------------------------------------------------------------------------
def test_to_public_json_contains_allowlist_fields() -> None:
    v = _safe_verdict()
    pub = v.to_public_json()
    assert set(pub.keys()) == {
        "address",
        "status",
        "finding",
        "confidence",
        "key_fingerprint",
        "recommendation",
        "evidence_refs",
        "audit_id",
        "checks_performed",
    }


def test_to_public_json_serializes_tuple_to_list() -> None:
    """JSON has no tuple; must convert tuple -> list."""
    v = _safe_verdict(checks_performed=("milk_sad", "randstorm"))
    pub = v.to_public_json()
    assert pub["checks_performed"] == ["milk_sad", "randstorm"]


def test_to_public_json_round_trips_through_json() -> None:
    """to_public_json output should be JSON-serializable."""
    import json

    v = _safe_verdict()
    serialized = json.dumps(v.to_public_json())
    parsed = json.loads(serialized)
    assert parsed["status"] == "SAFE"
    assert parsed["finding"] == "none"


# ---------------------------------------------------------------------------
# 10. Pickling / deepcopy a verdict — should work (it's a public output type).
# ---------------------------------------------------------------------------
def test_verdict_is_pickleable() -> None:
    """Verdicts are public output, pickling is fine (unlike Secret)."""
    import pickle

    v = _safe_verdict()
    data = pickle.dumps(v)
    restored = pickle.loads(data)
    assert restored == v


def test_verdict_equality() -> None:
    a = _safe_verdict()
    b = _safe_verdict()
    assert a == b
    c = _safe_verdict(confidence=0.5)
    assert a != c
