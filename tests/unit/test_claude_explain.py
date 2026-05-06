"""Unit tests for the ``wsa explain`` Claude wrapper.

These tests inject a fake ``call_fn`` so the SDK is never actually
invoked. The point is to validate the deterministic post-check (which
guards against LLM hallucinations) — that's where the real safety lives.
"""

from __future__ import annotations

import asyncio

import pytest

from wallet_self_audit.reporting.claude_explain import (
    ExplainPostCheckFailed,
    ExplainProvenance,
    explain_verdict,
)
from wallet_self_audit.verdict import VerdictWithoutKey


def _vulnerable() -> VerdictWithoutKey:
    return VerdictWithoutKey(
        address="bc1qexample",
        status="VULNERABLE",
        finding="r_collision",
        confidence=0.99,
        key_fingerprint="0123456789abcdef",
        recommendation="Move funds NOW.",
        evidence_refs=("a" * 64, "b" * 64),
        audit_id="33333333-3333-3333-3333-333333333333",
        checks_performed=("r_collision",),
    )


def _safe() -> VerdictWithoutKey:
    return VerdictWithoutKey(
        address="bc1qclean",
        status="SAFE",
        finding="none",
        confidence=0.95,
        key_fingerprint=None,
        recommendation="No matches for the configured vectors.",
        evidence_refs=(),
        audit_id="44444444-4444-4444-4444-444444444444",
        checks_performed=("milk_sad", "randstorm", "brainwallet"),
    )


def _make_call(fixed_response: str):  # type: ignore[no-untyped-def]
    """Return an async stub with the given response, callable like _call_claude."""

    async def _stub(*, model: str, system_prompt: str, user_prompt: str) -> str:
        # Touch the args so unused-variable lint doesn't fire if the stub is reused.
        _ = model, system_prompt, user_prompt
        return fixed_response

    return _stub


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------
def test_explain_happy_path_returns_markdown_and_provenance() -> None:
    fake_md = (
        "## Summary\nThis wallet is VULNERABLE due to r_collision.\n\n"
        "## Findings\n- r_collision\n\n"
        "## What this means\nNonce reuse leaks the private key.\n\n"
        "## Recommended actions\nMove funds NOW.\n"
    )
    md, prov = explain_verdict(_vulnerable(), call_fn=_make_call(fake_md))
    assert md == fake_md
    assert isinstance(prov, ExplainProvenance)
    assert prov.model_id == "claude-opus-4-7"
    assert len(prov.system_prompt_sha256) == 64
    assert len(prov.evidence_sha256) == 64
    assert len(prov.response_sha256) == 64


def test_explain_safe_verdict() -> None:
    """SAFE verdict must reference the literal finding value 'none'."""
    md = (
        "## Summary\nNo matches for the configured vectors.\n\n"
        "## Findings\n- milk_sad\n- randstorm\n- brainwallet\n\n"
        "## What this means\nThe finding is none for now.\n\n"
        "## Recommended actions\nKeep airgap discipline.\n"
    )
    out, _ = explain_verdict(_safe(), call_fn=_make_call(md))
    assert "none" in out


# ---------------------------------------------------------------------------
# Post-check rejections
# ---------------------------------------------------------------------------
def test_explain_rejects_missing_finding_reference() -> None:
    """If Claude doesn't echo the finding code verbatim, reject."""
    bad = (
        "## Summary\nSomething is wrong.\n\n"
        "## Findings\n- nonce-reuse\n"  # paraphrased — should be `r_collision`
        "\n## What this means\nKey leak.\n\n"
        "## Recommended actions\nMove funds.\n"
    )
    with pytest.raises(ExplainPostCheckFailed, match="finding"):
        explain_verdict(_vulnerable(), call_fn=_make_call(bad))


def test_explain_rejects_unknown_64_hex() -> None:
    """A 64-hex string not in evidence_refs looks like a privkey leak."""
    leaked = "deadbeef" * 8  # 64 hex chars not in evidence_refs
    bad = (
        "## Summary\nVULNERABLE r_collision.\n\n"
        "## Findings\n- r_collision\n\n"
        f"## What this means\nDetail: {leaked}\n\n"
        "## Recommended actions\nMove funds NOW.\n"
    )
    with pytest.raises(ExplainPostCheckFailed, match="64-char hex"):
        explain_verdict(_vulnerable(), call_fn=_make_call(bad))


def test_explain_accepts_evidence_txid_in_text() -> None:
    """64-hex strings that ARE in evidence_refs are allowed."""
    txid_a = "a" * 64
    md = (
        "## Summary\nVULNERABLE r_collision\n\n"
        "## Findings\n- r_collision\n\n"
        f"## What this means\nSee tx {txid_a}\n\n"
        "## Recommended actions\nMove funds NOW.\n"
    )
    out, _ = explain_verdict(_vulnerable(), call_fn=_make_call(md))
    assert txid_a in out


def test_explain_rejects_bip39_mnemonic_pattern() -> None:
    bad = (
        "## Summary\nr_collision\n\n"
        "## Findings\n- r_collision\n\n"
        "## What this means\n"
        "abandon abandon abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon about\n\n"
        "## Recommended actions\nMove funds NOW.\n"
    )
    with pytest.raises(ExplainPostCheckFailed, match="BIP-39"):
        explain_verdict(_vulnerable(), call_fn=_make_call(bad))


def test_explain_rejects_private_key_recovered_claim() -> None:
    bad = (
        "## Summary\nThe private key recovered itself.\n\n"
        "## Findings\n- r_collision\n\n"
        "## What this means\nKey was leaked.\n\n"
        "## Recommended actions\nMove funds NOW.\n"
    )
    with pytest.raises(ExplainPostCheckFailed, match="recovered"):
        explain_verdict(_vulnerable(), call_fn=_make_call(bad))


# ---------------------------------------------------------------------------
# Provenance
# ---------------------------------------------------------------------------
def test_provenance_hashes_change_with_response() -> None:
    """Different LLM drafts → different response hashes; identical inputs
    → identical system / evidence hashes."""
    text_a = (
        "## Summary\nA r_collision.\n## Findings\n- r_collision\n"
        "## What this means\nfoo\n## Recommended actions\nmove now\n"
    )
    text_b = (
        "## Summary\nB r_collision.\n## Findings\n- r_collision\n"
        "## What this means\nbar\n## Recommended actions\nmove now\n"
    )
    _, prov_a = explain_verdict(_vulnerable(), call_fn=_make_call(text_a))
    _, prov_b = explain_verdict(_vulnerable(), call_fn=_make_call(text_b))
    assert prov_a.system_prompt_sha256 == prov_b.system_prompt_sha256
    assert prov_a.evidence_sha256 == prov_b.evidence_sha256
    assert prov_a.response_sha256 != prov_b.response_sha256


# ---------------------------------------------------------------------------
# Async stub plumbing — make sure asyncio.run() handles us cleanly.
# ---------------------------------------------------------------------------
def test_async_stub_can_be_awaited_directly() -> None:
    stub = _make_call("text")
    out = asyncio.run(stub(model="x", system_prompt="y", user_prompt="z"))
    assert out == "text"
