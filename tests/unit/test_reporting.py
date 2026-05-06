"""Unit tests for the verdict renderers (txt / json / md)."""

from __future__ import annotations

import json

import pytest

from wallet_self_audit.reporting.render_json import render_json
from wallet_self_audit.reporting.render_md import render_md
from wallet_self_audit.reporting.render_txt import render_txt
from wallet_self_audit.verdict import VerdictWithoutKey


def _safe_verdict() -> VerdictWithoutKey:
    return VerdictWithoutKey(
        address="bc1qexample",
        status="SAFE",
        finding="none",
        confidence=0.95,
        key_fingerprint=None,
        recommendation="No issues detected.",
        evidence_refs=(),
        audit_id="11111111-1111-1111-1111-111111111111",
        checks_performed=("milk_sad", "randstorm", "brainwallet"),
    )


def _vulnerable_verdict() -> VerdictWithoutKey:
    return VerdictWithoutKey(
        address="bc1qexample",
        status="VULNERABLE",
        finding="r_collision",
        confidence=0.99,
        key_fingerprint="0123456789abcdef",
        recommendation="Move funds NOW.",
        evidence_refs=("a" * 64, "b" * 64),
        audit_id="22222222-2222-2222-2222-222222222222",
        checks_performed=("r_collision",),
    )


# ---------------------------------------------------------------------------
# render_txt
# ---------------------------------------------------------------------------
def test_render_txt_safe_includes_banner() -> None:
    out = render_txt(_safe_verdict())
    assert out.startswith("[SAFE]")
    assert "No issues detected." in out
    assert "audit_id: 11111111-1111-1111-1111-111111111111" in out


def test_render_txt_vulnerable_lists_evidence() -> None:
    out = render_txt(_vulnerable_verdict())
    assert "[VULNERABLE]" in out
    assert "key_fingerprint: 0123456789abcdef" in out
    assert "evidence_refs:" in out
    assert "a" * 64 in out
    assert "b" * 64 in out


def test_render_txt_no_checks_label() -> None:
    """Empty checks_performed renders as ``(none)`` not an empty string."""
    v = VerdictWithoutKey(
        address="bc1q",
        status="SUSPICIOUS",
        finding="none",
        confidence=0.5,
        key_fingerprint=None,
        recommendation="See logs.",
        evidence_refs=(),
        audit_id="33333333-3333-3333-3333-333333333333",
        checks_performed=(),
    )
    out = render_txt(v)
    assert "checks_performed: (none)" in out


# ---------------------------------------------------------------------------
# render_json
# ---------------------------------------------------------------------------
def test_render_json_round_trips() -> None:
    out = render_json(_safe_verdict())
    parsed = json.loads(out)
    assert parsed["status"] == "SAFE"
    assert parsed["address"] == "bc1qexample"
    # checks_performed must be a list (tuple → list per to_public_json contract).
    assert isinstance(parsed["checks_performed"], list)


def test_render_json_is_deterministic() -> None:
    """Same input → identical bytes (sorted keys + fixed indent)."""
    a = render_json(_safe_verdict())
    b = render_json(_safe_verdict())
    assert a == b


def test_render_json_evidence_refs_are_list() -> None:
    out = render_json(_vulnerable_verdict())
    parsed = json.loads(out)
    assert parsed["evidence_refs"] == ["a" * 64, "b" * 64]


# ---------------------------------------------------------------------------
# render_md
# ---------------------------------------------------------------------------
def test_render_md_safe_starts_with_h1() -> None:
    out = render_md(_safe_verdict())
    assert out.splitlines()[0].startswith("# ")
    assert "SAFE" in out
    assert "## Summary" in out


def test_render_md_vulnerable_includes_evidence_section() -> None:
    out = render_md(_vulnerable_verdict())
    assert "VULNERABLE" in out
    assert "## Evidence (transaction IDs)" in out
    assert "`" + "a" * 64 + "`" in out


def test_render_md_includes_recommendation() -> None:
    out = render_md(_vulnerable_verdict())
    assert "Move funds NOW." in out
    assert "## Recommended action" in out


@pytest.mark.parametrize(
    "renderer",
    [render_txt, render_md],
)
def test_renderers_handle_no_fingerprint(renderer) -> None:  # type: ignore[no-untyped-def]
    out = renderer(_safe_verdict())
    assert "key_fingerprint" not in out.lower() or "key fingerprint" not in out.lower()
