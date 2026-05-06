"""End-to-end no-key-leak tests for every renderer surface.

Phase 8 hardening: feed a verdict known to be the most "key-shaped" one
the type system permits (long fingerprint, two long-hex evidence_refs,
recommendation full of letters), then run it through every reporter and
prove that:

1. No 64-char hex run other than ``evidence_refs`` appears.
2. No BIP-39-shaped 12-24 lowercase-word run appears.
3. No literal substring "private key recovered" appears.

This is the regression test that ``wsa explain`` adds *another* layer
of post-checking on top of — but the three local renderers are pure
formatting and must obey the same rules.
"""

from __future__ import annotations

import re

import pytest

from wallet_self_audit.reporting.render_json import render_json
from wallet_self_audit.reporting.render_md import render_md
from wallet_self_audit.reporting.render_txt import render_txt
from wallet_self_audit.verdict import VerdictWithoutKey

_PRIVKEY_HEX = re.compile(r"\b[0-9a-fA-F]{64}\b")
_BIP39_LIKE = re.compile(r"\b(?:[a-z]{3,8}\s+){11,23}[a-z]{3,8}\b")


@pytest.fixture
def adversarial_verdict() -> VerdictWithoutKey:
    """A verdict with maximally-key-shaped public surface still passes invariants."""
    return VerdictWithoutKey(
        address="bc1qmaximallyadversarialaddress00000000",
        status="VULNERABLE",
        finding="r_collision",
        confidence=0.99,
        key_fingerprint="0123456789abcdef",
        recommendation=(
            "Move funds to a fresh wallet IMMEDIATELY. The signing key is "
            "recoverable from public chain data."
        ),
        evidence_refs=("a" * 64, "b" * 64, "c" * 64),
        audit_id="11111111-1111-1111-1111-111111111111",
        checks_performed=("r_collision", "lattice_bias"),
    )


def _allowed_64hex(verdict: VerdictWithoutKey) -> set[str]:
    """64-char hex strings that are LEGITIMATELY in any renderer output."""
    # Only evidence_refs are 64-hex by spec.
    return {ref.lower() for ref in verdict.evidence_refs}


@pytest.mark.parametrize(
    "renderer",
    [render_txt, render_json, render_md],
)
def test_renderer_emits_no_unknown_64hex(renderer, adversarial_verdict: VerdictWithoutKey) -> None:  # type: ignore[no-untyped-def]
    out = renderer(adversarial_verdict)
    allowed = _allowed_64hex(adversarial_verdict)
    for match in _PRIVKEY_HEX.finditer(out):
        h = match.group(0).lower()
        assert h in allowed, f"{renderer.__name__} leaked a 64-hex string not in evidence_refs: {h}"


@pytest.mark.parametrize(
    "renderer",
    [render_txt, render_json, render_md],
)
def test_renderer_emits_no_bip39_pattern(renderer, adversarial_verdict: VerdictWithoutKey) -> None:  # type: ignore[no-untyped-def]
    out = renderer(adversarial_verdict)
    assert _BIP39_LIKE.search(out) is None, f"{renderer.__name__} produced a BIP-39-shaped run"


@pytest.mark.parametrize(
    "renderer",
    [render_txt, render_json, render_md],
)
def test_renderer_does_not_claim_key_recovered(
    renderer, adversarial_verdict: VerdictWithoutKey
) -> None:  # type: ignore[no-untyped-def]
    out = renderer(adversarial_verdict).lower()
    assert "private key recovered" not in out
    assert "key was recovered" not in out


def test_safe_verdict_has_no_fingerprint_in_any_renderer() -> None:
    """For a SAFE verdict, key_fingerprint is None and must not appear."""
    v = VerdictWithoutKey(
        address="bc1qclean",
        status="SAFE",
        finding="none",
        confidence=0.95,
        key_fingerprint=None,
        recommendation="No matches for the configured vectors.",
        evidence_refs=(),
        audit_id="22222222-2222-2222-2222-222222222222",
        checks_performed=("milk_sad", "randstorm", "brainwallet"),
    )
    for renderer in (render_txt, render_json, render_md):
        out = renderer(v)
        assert "0123456789abcdef" not in out  # arbitrary fixture fingerprint
